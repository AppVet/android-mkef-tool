/* This software was developed by employees of the National Institute of
 * Standards and Technology (NIST), an agency of the Federal Government.
 * Pursuant to title 15 United States Code Section 105, works of NIST
 * employees are not subject to copyright protection in the United States
 * and are considered to be in the public domain.  As a result, a formal
 * license is not needed to use the software.
 * 
 * This software is provided by NIST as a service and is expressly
 * provided "AS IS".  NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
 * OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
 * AND DATA ACCURACY.  NIST does not warrant or make any representations
 * regarding the use of the software or the results thereof including, but
 * not limited to, the correctness, accuracy, reliability or usefulness of
 * the software.
 * 
 * Permission to use this software is contingent upon your acceptance
 * of the terms of this agreement.
 */
package gov.nist.appvet.tool.androidmkef;

import gov.nist.appvet.tool.androidmkef.util.FileUtil;
import gov.nist.appvet.tool.androidmkef.util.HttpUtil;
import gov.nist.appvet.tool.androidmkef.util.Logger;
import gov.nist.appvet.tool.androidmkef.util.Protocol;
import gov.nist.appvet.tool.androidmkef.util.ReportFormat;
import gov.nist.appvet.tool.androidmkef.util.ReportUtil;
import gov.nist.appvet.tool.androidmkef.util.ToolStatus;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.FileUtils;

/**
 * This class implements a synchronous tool service.
 */
public class Service extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final String reportName = "report";
	private static final Logger log = Properties.log;
	private static String appDirPath = null;
	private String appFilePath = null;
	private String iconFilePath = null;
	private String htmlFileReportPath = null;
	private String pdfFileReportPath = null;
	private String fileName = null;
	private String appId = null;
	private StringBuffer reportBuffer = null;

	public Service() {
		super();
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		// Get received HTTP parameters and file upload
		FileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload upload = new ServletFileUpload(factory);
		List<FileItem> items = null;
		FileItem appFileItem = null;
		FileItem iconFileItem = null;

		try {
			items = upload.parseRequest(request);
		} catch (FileUploadException e) {
			e.printStackTrace();
		}

		// Get received items
		Iterator<FileItem> iter = items.iterator();
		FileItem item = null;

		while (iter.hasNext()) {
			item = (FileItem) iter.next();
			if (item.isFormField()) {
				// Get HTML form parameters
				String incomingParameter = item.getFieldName();
				String incomingValue = item.getString();
				if (incomingParameter.equals("appid")) {
					appId = incomingValue;
				}
			} else {
				// item is a file
				if (item != null) {
					if (item.getName().endsWith(".apk")) {
						appFileItem = item;
						log.debug("Received app: " + appFileItem.getName());
					} else if (item.getName().endsWith(".png")){
						iconFileItem = item;
						log.debug("Received icon: " + iconFileItem.getName());
					}
				}
			}
		}

		if (appId == null) {
			// All tool services require an AppVet app ID
			HttpUtil.sendHttp400(response, "No app ID specified");
			return;
		}

		if (appFileItem != null && iconFileItem != null) {
			// Get app file
			fileName = FileUtil.getFileName(appFileItem.getName());
			// Must be an APK file
			if (!fileName.endsWith(".apk")) {
				HttpUtil.sendHttp400(response,
						"Invalid app file: " + appFileItem.getName());
				return;
			}

			// Create app directory
			appDirPath = Properties.TEMP_DIR + "/" + appId;
			File appDir = new File(appDirPath);
			if (!appDir.exists()) {
				appDir.mkdir();
			}

			// Create report paths
			htmlFileReportPath = appDirPath + "/"
					+ reportName + "." + Properties.reportFormat.toLowerCase();
			pdfFileReportPath = appDirPath + "/"
					+ reportName + ".pdf";

			appFilePath = appDirPath + "/" + fileName;
			iconFilePath = appDirPath + "/icon.png";

			if (!FileUtil.saveFileUpload(appFileItem, appFilePath)) {
				HttpUtil.sendHttp500(response, "Could not save app");
				return;
			}
			
			if (!FileUtil.saveFileUpload(iconFileItem, iconFilePath)) {
				HttpUtil.sendHttp500(response, "Could not save icon");
				return;
			}
			
		} else {
			HttpUtil.sendHttp400(response, "No app or icon was received.");
			return;
		}

		// If asynchronous, send acknowledgement back to AppVet
		if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
			HttpUtil.sendHttp202(response, "Received app " + appId
					+ " for processing.");
		}

		reportBuffer = new StringBuffer();

		// Start processing app
		log.debug("Executing MKEF on app");
		double score = analyzeMkef(reportBuffer);
		System.out.println("MKEF score: " + score);

		// Analyze report and generate tool status
		log.debug("Analyzing report for " + appFilePath);
		ToolStatus reportStatus = null;
		if (score < 0.0) {
			reportStatus = ToolStatus.ERROR;
		} else if (score == 0.0) {
			reportStatus = ToolStatus.LOW;
		} else if (score == 10.0) {
			reportStatus = ToolStatus.HIGH;
		} else {
			reportStatus = ToolStatus.ERROR;
		}
		log.debug("Result: " + reportStatus.name());
		String reportContent = null;

		// Get report TODO Fix HTML requirement here
		if (Properties.reportFormat.equals(ReportFormat.HTML.name())) {
			reportContent = ReportUtil
					.getHtmlReport(
							response,
							fileName,
							reportStatus,
							reportBuffer.toString(),
							"Description: \tApp does not contain Android MasterKey or ExtraField vulnerabilities.\n\n",
							null,
							"Description: \tApp contains Android MasterKey and/or ExtraField vulnerabilities.\n\n",
							"Description: \tError or exception processing app.\n\n");
		}

		// If report content is null or empty, stop processing
		if (reportContent == null || reportContent.isEmpty()) {
			log.error("Tool report is null or empty");
			return;
		}

		// Send report to AppVet
		if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
			// Send report file in new HTTP Request to AppVet
			boolean htmlFileSaved = FileUtil.saveReport(reportContent,
					htmlFileReportPath);
			if (htmlFileSaved) {
				final StringBuffer reportBuffer = new StringBuffer();
				boolean htmlToPdfSuccessful = execute(Properties.htmlToPdfCommand + " " 
						+ htmlFileReportPath + " " + pdfFileReportPath,
						reportBuffer);
				if (htmlToPdfSuccessful) {
					ReportUtil.sendInNewHttpRequest(appId, pdfFileReportPath,
							score, reportStatus);
				} else {
					log.error("Error generating PDF file " + pdfFileReportPath);
				}
			} else {
				log.error("Error writing HTML report " + htmlFileReportPath);
			}
		}

		// Clean up
		if (!Properties.keepApps) {
			try {
				log.debug("Removing app " + appId + " files.");
				FileUtils.deleteDirectory(new File(appDirPath));
			} catch (IOException ioe) {
				log.error(ioe.getMessage());
			}
		}

		reportBuffer = null;

		// Clean up
		System.gc();
	}

	/** If no Master Key found, return toolscore=0.0. If found, return toolscore=10.0. */
	public double analyzeMkef(StringBuffer output) {
		log.debug("Creating MKEFScanner");
		MKEFScanner mkefScan = new MKEFScanner(appFilePath);
		log.debug("Created MKEFScanner");

		if (mkefScan.hasMasterKey()) {
			mkefScan.close();
			// The following String MUST match in ToolProperties.xml
			System.out.println("Android MasterKey vulnerability detected.");
			output.append("Android MasterKey vulnerability detected.");
			return 10.0;
		} else if (mkefScan.hasExtraField()) {
			mkefScan.close();
			// The following String MUST match in ToolProperties.xml
			System.out.println("Android ExtraField vulnerability detected.");
			output.append("Android ExtraField vulnerability detected.");
			return 10.0;
		} else {
			log.debug("Mo Master Key found");
			mkefScan.close();
			System.out.println("No Android MaskterKey or ExtraField vulnerabilities detected.");
			output.append("No Android MaskterKey or ExtraField vulnerabilities detected.");
		}
		return 0.0;
	}

	/**
	 * IMPORTANT: Make sure that tool to execute is in a user-owned directory
	 * with executable permissions for root. Otherwise, the tool may not execute
	 * properly.
	 */
	private boolean execute(String command, StringBuffer output) {
		List<String> commandArgs = Arrays.asList(command.split("\\s+"));
		ProcessBuilder pb = new ProcessBuilder(commandArgs);
		Process process = null;
		IOThreadHandler outputHandler = null;
		IOThreadHandler errorHandler = null;
		int exitValue = -1;
		try {
			process = pb.start();
			outputHandler = new IOThreadHandler(process.getInputStream());
			outputHandler.start();
			errorHandler = new IOThreadHandler(process.getErrorStream());
			errorHandler.start();
			if (process.waitFor(300000, TimeUnit.MILLISECONDS)) {
				// Process has waited and exited within the timeout
				exitValue = process.exitValue();
				if (exitValue == 0) {
					StringBuffer resultOut = outputHandler.getOutput();
					output.append(resultOut);
					return true;
				} else {
					StringBuffer resultError = errorHandler.getOutput();
					output.append(resultError);
					return false;
				}
			} else {
				// Process exceed timeout or was interrupted
				StringBuffer resultOutput = outputHandler.getOutput();
				StringBuffer resultError = errorHandler.getOutput();
				if (resultOutput != null) {
					output.append(resultOutput);
				} else if (resultError != null) {
					output.append(resultError);
				} else {
					output.append("Apktool timed-out");
				}
				return false;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return false;
		} finally {
			if (outputHandler != null && outputHandler.isAlive()) {
				try {
					outputHandler.inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (errorHandler != null && errorHandler.isAlive()) {
				try {
					errorHandler.inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (process != null && process.isAlive()) {
				process.destroy();
			}
		}
	}

	private class IOThreadHandler extends Thread {
		private InputStream inputStream;
		private StringBuffer output = new StringBuffer();
		private final String lineSeparator = System
				.getProperty("line.separator");

		IOThreadHandler(InputStream inputStream) {
			this.inputStream = inputStream;
		}

		public void run() {
			Scanner br = null;
			br = new Scanner(new InputStreamReader(inputStream));
			String line = null;
			while (br.hasNextLine()) {
				line = br.nextLine();
				output.append(line + lineSeparator);
			}
			br.close();
		}

		public StringBuffer getOutput() {
			return output;
		}
	}
}
