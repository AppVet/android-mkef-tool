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
import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

/**
 * This class implements a synchronous tool service.
 */
public class Service extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final String reportName = "report";
	private static final Logger log = Properties.log;
	private static String appDirPath = null;
	private String appFilePath = null;
	private String reportFilePath = null;
	private String fileName = null;
	private String appId = null;
	private StringBuffer reportBuffer = null;

	/** CHANGE (START): Add expected HTTP request parameters **/
	/** CHANGE (END): Add expected HTTP request parameters **/
	public Service() {
		super();
	}

	/*
	 * // AppVet tool services will rarely use HTTP GET protected void
	 * doGet(HttpServletRequest request, HttpServletResponse response) throws
	 * ServletException, IOException {
	 */

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		// Get received HTTP parameters and file upload
		FileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload upload = new ServletFileUpload(factory);
		List items = null;
		FileItem fileItem = null;

		try {
			items = upload.parseRequest(request);
		} catch (FileUploadException e) {
			e.printStackTrace();
		}

		// Get received items
		Iterator iter = items.iterator();
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
				/** CHANGE (START): Get other tools-specific form parameters **/
				/** CHANGE (END): Get other tools-specific form parameters **/
			} else {
				// item should now hold the received file
				if (item != null) {
					fileItem = item;
					log.debug("Received file: " + fileItem.getName());
				}
			}
		}

		if (appId == null) {
			// All tool services require an AppVet app ID
			HttpUtil.sendHttp400(response, "No app ID specified");
			return;
		}

		if (fileItem != null) {
			// Get app file
			fileName = FileUtil.getFileName(fileItem.getName());
			if (!fileName.endsWith(".apk")) {
				HttpUtil.sendHttp400(response,
						"Invalid app file: " + fileItem.getName());
				return;
			}

			// Create app directory
			appDirPath = Properties.TEMP_DIR + "/" + appId;
			File appDir = new File(appDirPath);
			if (!appDir.exists()) {
				appDir.mkdir();
			}

			// Create report path
			reportFilePath = Properties.TEMP_DIR + "/" + appId + "/"
					+ reportName + "." + Properties.reportFormat.toLowerCase();
			appFilePath = Properties.TEMP_DIR + "/" + appId + "/" + fileName;

			if (!FileUtil.saveFileUpload(fileItem, appFilePath)) {
				HttpUtil.sendHttp500(response, "Could not save uploaded file");
				return;
			}
		} else {
			HttpUtil.sendHttp400(response, "No app was received.");
			return;
		}

		// Use if reading command from ToolProperties.xml. Otherwise,
		// comment-out if using custom command (called by customExecute())
		// command = getCommand();
		reportBuffer = new StringBuffer();

		// If asynchronous, send acknowledgement back to AppVet so AppVet
		// won't block waiting for a response.
		if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
			HttpUtil.sendHttp202(response, "Received app " + appId
					+ " for processing.");
		}

		/*
		 * CHANGE: Select either execute() to execute a native OS command or
		 * customExecute() to execute your own custom code. Make sure that the
		 * unused method call is commented-out.
		 */
		// boolean succeeded = execute(command, reportBuffer);
		boolean succeeded = customExecute(reportBuffer);

		if (!succeeded) {
			log.error("Error detected: " + reportBuffer.toString());
			String errorReport = ReportUtil
					.getHtmlReport(
							response,
							fileName,
							ToolStatus.ERROR,
							reportBuffer.toString(),
							"Description: \tApp does not contain Android MasterKey or ExtraField vulnerabilities.\n\n",
							null,
							"Description: \tApp contains Android MasterKey and/or ExtraField vulnerabilities.\n\n",
							"Description: \tError or exception processing app.\n\n");
			// Send report to AppVet
			if (Properties.protocol.equals(Protocol.SYNCHRONOUS.name())) {
				// Send back ASCII in HTTP Response
				ReportUtil.sendInHttpResponse(response, errorReport,
						ToolStatus.ERROR);
			} else if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
				// Send report file in new HTTP Request to AppVet
				if (FileUtil.saveReport(errorReport, reportFilePath)) {
					ReportUtil.sendInNewHttpRequest(appId, reportFilePath,
							ToolStatus.ERROR);
				}
			}
			return;
		}

		// Analyze report and generate tool status
		log.debug("Analyzing report for " + appFilePath);
		ToolStatus reportStatus = analyzeReport(reportBuffer
				.toString());
		log.debug("Result: " + reportStatus.name());
		String reportContent = null;

		// Get report
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
		} else if (Properties.reportFormat.equals(ReportFormat.TXT.name())) {
			reportContent = getTxtReport();
		} else if (Properties.reportFormat.equals(ReportFormat.PDF.name())) {
			reportContent = getPdfReport();
		} else if (Properties.reportFormat.equals(ReportFormat.JSON.name())) {
			reportContent = getJsonReport();
		}

		// If report content is null or empty, stop processing
		if (reportContent == null || reportContent.isEmpty()) {
			log.error("Tool report is null or empty");
			return;
		}

		// Send report to AppVet
		if (Properties.protocol.equals(Protocol.SYNCHRONOUS.name())) {
			// Send back ASCII in HTTP Response
			ReportUtil
			.sendInHttpResponse(response, reportContent, reportStatus);
		} else if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
			// Send report file in new HTTP Request to AppVet
			if (FileUtil.saveReport(reportContent, reportFilePath)) {
				ReportUtil.sendInNewHttpRequest(appId, reportFilePath,
						reportStatus);
			}
		}

		// Clean up
		if (!Properties.keepApps) {
			if (FileUtil.deleteDirectory(new File(appDirPath))) {
				log.debug("Deleted " + appFilePath);
			} else {
				log.warn("Could not delete " + appFilePath);
			}
		}

		reportBuffer = null;

		// Clean up
		System.gc();
	}
	
    public static ToolStatus analyzeReport(String report) {
	if (report == null || report.isEmpty()) {
	    log.error("Report is null or empty.");
	    return ToolStatus.ERROR;
	}
	// Scan file for result strings defined in configuration file. Here,
	// we always scan in this order: ERRORs, HIGHs, MODERATEs, and LOWs.
	if (Properties.errorResults != null
		&& !Properties.errorResults.isEmpty()) {
	    for (String s : Properties.errorResults) {
		if (report.indexOf(s) > -1) {
		    log.debug("Error message: " + s);
		    return ToolStatus.ERROR;
		}
	    }
	}
	if (Properties.highResults != null && !Properties.highResults.isEmpty()) {
	    for (String s : Properties.highResults) {
		if (report.indexOf(s) > -1) {
		    log.debug("High message: " + s);
		    return ToolStatus.HIGH;
		}
	    }
	}
	if (Properties.moderateResults != null
		&& !Properties.moderateResults.isEmpty()) {
	    for (String s : Properties.moderateResults) {
		if (report.indexOf(s) > -1) {
		    log.debug("Moderate message: " + s);
		    return ToolStatus.MODERATE;
		}
	    }
	}
	if (Properties.lowResults != null && !Properties.lowResults.isEmpty()) {
	    for (String s : Properties.lowResults) {
		if (report.indexOf(s) > -1) {
		    log.debug("Low message: " + s);
		    return ToolStatus.LOW;
		}
	    }
	}
	return Properties.defaultStatus;
    }

	public boolean customExecute(StringBuffer output) {
		MKEFScanner mkefScan = new MKEFScanner(appFilePath);
		if (mkefScan.hasMasterKey()) {
			// The following String MUST match in ToolProperties.xml
			output.append("Android MasterKey vulnerability detected.");
			return true;
		} else if (mkefScan.hasExtraField()) {
			// The following String MUST match in ToolProperties.xml
			output.append("Android ExtraField vulnerability detected.");
			return true;
		} else {
			output.append("No Android MaskterKey or ExtraField vulnerabilities detected.");
		}
		return true;
	}

	// TODO
	public String getTxtReport() {
		return null;
	}

	// TODO
	public String getPdfReport() {
		return null;
	}

	// TODO
	public String getJsonReport() {
		return null;
	}

}
