package burp.test;

import java.net.MalformedURLException;
import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

/* Copyright (c) 2014, Bryant Zadegan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

public class TestIScanIssueImpl implements IScanIssue {

	@Override
	public String getConfidence() {
		return "Tentative";
	}

	@Override
	public String getHost() {
		return "127.255.255.254";
	}

	@Override
	public URL getUrl() {
		try {
			return new URL("http://TestIScanIssueImpl.burp");
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getIssueName() {
		return "Test Issue Name";
	}

	@Override
	public int getIssueType() {
		return 0;
	}

	@Override
	public String getSeverity() {
		return "Information";
	}

	@Override
	public String getIssueBackground() {
		return "This is a test background description for testing the fillParams function." 
		+"<br />"
		+"<br /><b>Test Selective Escape</b>"
		+"<br />This is a test of the \"selectiveEscape\" method via IssueBackground.";
	}

	@Override
	public String getRemediationBackground() {
		return "Remediation Information for an issue will take the place of this text.";
	}

	@Override
	public String getIssueDetail() {
		return "Issue details will take the place of this text.";
	}

	@Override
	public String getRemediationDetail() {
		return "Remediation details will take the place of this text.";
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		// XXX: Yeah this isn't being implemented until everything else is done. Returns null.
		return null;
	}

	@Override
	public IHttpService getHttpService() {
		// XXX: This may or may not resolve with the toString on the reflected method call. We'll see.
		return null;
	}

	@Override
	public int getPort() {
		return 0;
	}

	@Override
	public String getProtocol() {
		return "HTTP";
	}
	
}
