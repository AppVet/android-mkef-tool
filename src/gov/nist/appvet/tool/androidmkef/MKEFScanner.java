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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class MKEFScanner {
	ZipFile apkFile = null;

	public MKEFScanner(String apkPath) {
		try {
			apkFile = new ZipFile(apkPath);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean hasMasterKey() {
		Enumeration<? extends ZipEntry> apkFileEntries = apkFile.entries();
		ArrayList<String> entries = new ArrayList<String>();

		while (apkFileEntries.hasMoreElements()) {
			String entry = apkFileEntries.nextElement().toString();
			if (!entries.contains(entry)) {
				entries.add(entry);
			} else {
				// Duplicate found
				return true;
			}
		}
		return false;
	}

	public boolean hasExtraField() {
		Enumeration<? extends ZipEntry> apkFileEntries = apkFile.entries();
		try {
			while (apkFileEntries.hasMoreElements()) {
				ZipEntry entry = apkFileEntries.nextElement();
				InputStream inputStream = apkFile.getInputStream(entry);
				int numBytesRead;
				byte[] byteArray = new byte[1024];
				ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
				while ((numBytesRead = inputStream.read(byteArray, 0,
						byteArray.length)) != -1) {
					byteArrayOutputStream.write(byteArray, 0, numBytesRead);
				}
				byte[] bytes = byteArrayOutputStream.toByteArray();
				CRC32 cs = new CRC32();
				cs.update(bytes);
				if (cs.getValue() != entry.getCrc()) {
					return true;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	public void close() {
		if (apkFile != null) {
			try {
				apkFile.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}