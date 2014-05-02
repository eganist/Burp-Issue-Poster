package burp;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.apache.commons.lang3.StringUtils;

import burp.test.TestIScanIssueImpl;
import burp.utils.PostUtils;

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

public class BurpExtender implements IBurpExtender, IScannerListener,
IExtensionStateListener
{
	private boolean debug = false;
	private IBurpExtenderCallbacks callbacks;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private HttpClient client;
	private List<String> postFile;
	private List<Header> headers = new ArrayList<Header>();
	private static URL reportingUrl;
	private String Confidence = "Firm"; //send only certain findings by default. Arbitrary decision.
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
		this.client = HttpClientBuilder.create().build();
		callbacks.setExtensionName("Burp Issue Poster");
		if (stdout == null && stderr == null) {
			stdout = new PrintWriter(callbacks.getStdout(), true);
			stderr = new PrintWriter(callbacks.getStderr(), true);
		}
		
		boolean validTemplate = false;
		do{
			postFile = new ArrayList<String>();
			
			//load template from file
			try{
				int scopeConfigured = JOptionPane.showConfirmDialog(null, "Have you narrowed your scanner scope? "
                		+"\n(clicking 'no' will unload this extension to give you a moment to narrow your scope.)","Warning",JOptionPane.YES_NO_OPTION);

                if(scopeConfigured == JOptionPane.NO_OPTION){
                	stdout.println("User desires to narrow scanner scope. Extension unloaded.");
	            	callbacks.unloadExtension();
	            	return;
                }
				JFileChooser fc = new JFileChooser();
				int returnVal = fc.showOpenDialog(null);
				stdout.println("Prompting for POST file.");
	            if (returnVal == JFileChooser.APPROVE_OPTION) {
	                File file = fc.getSelectedFile();
	                
	                /*Enable debug if the template filename has ".debug" anywhere (e.g. bip.debug.txt).
	                 *There's better ways of doing this, but as no GUI has been implemented yet, the
	                 *decision is to determine the debug pattern based on whether it's present in the
	                 *filename of the POST template.
	                 */  
	                if(file.getName().toLowerCase().contains(".debug")){
	                	setDebug(true); 
	                	stdout.print("Debug enabled. ");
	                }
	                stdout.println("Reading POST template from " + file.toPath().toAbsolutePath() + "...");
	                postFile.addAll(Files.readAllLines(file.toPath(), Charset.defaultCharset()));
	                stdout.println("...done!");
	            } else {
	            	stdout.println("User canceled file-open. Extension unloaded.");
	            	callbacks.unloadExtension();
	            	return;
	            }
			} 
		    catch (NoSuchFileException nsfe) {
		    	stderr.println("POST file not found. Extension Unloaded.");
		    	callbacks.unloadExtension();
		    } 
		    catch (IOException ioe) {ioe.printStackTrace(stderr);callbacks.unloadExtension();} 
		    catch (Exception e){e.printStackTrace(stderr);callbacks.unloadExtension();} 
			
			//prompt for confidence level
			this.chooseConfidence();
			stdout.println("Confidence minimum set to " + Confidence + ".");
			
			try{
				setReportingUrl(postFile.remove(0));
			} catch(MalformedURLException murle) {
				stderr.println("Reporting URL is improperly formated. First line should be the exact POST target, no quotes."
	    				+"\nOnce complete, reload this extension.");
				callbacks.unloadExtension();
			}
			
			//remove comments, peel headers. All that's left after these two calls is 
			postFile = PostUtils.deComment(postFile);		
			this.setHeaders(postFile);
			
			//template test. If this throws a NoSuchMethodException, we'll try again.
			try{
				PostUtils.fillParams(postFile, new TestIScanIssueImpl());
				validTemplate = true;
			} catch(NoSuchMethodException nsme) {
				
				stderr.println(nsme.getMessage());
			} catch(Exception e) {
				stderr.println(e.getMessage());
				callbacks.unloadExtension();
				return;
			}
		} while(validTemplate == false);
		
		//all prepwork is done. We can now register this as a scanner listener.
		callbacks.registerScannerListener(this);
		callbacks.registerExtensionStateListener(this);
	}
	
	@Override
	public void newScanIssue(IScanIssue issue) {
		if (checkConfidence(issue.getConfidence())){
			try{
				List<String> postedFile;
				postedFile = PostUtils.fillParams(postFile, issue);
				
				//build POST
				HttpPost post = new HttpPost(reportingUrl.toURI());
				StringEntity input = new StringEntity(PostUtils.convertListToString(postedFile));
			    if (debug == true) {
			    	stdout.println("Debug enabled. Filled POST request body:\n"
			    			+ PostUtils.convertListToString(postedFile));
			    }
			    post.setEntity(input);
			    for(Header header : headers){
			    	post.addHeader(header);
			    }
			    
			    //execute POST
			    HttpResponse response = client.execute(post);
			    
			    //get POST response and evaluate whether to report.
			    String responseAsString = EntityUtils.toString(response.getEntity());
			    StatusLine responseStatus = response.getStatusLine();
			    if(PostUtils.checkSuccess(responseStatus.getStatusCode()))
			    {
			    	if (debug == true) {
			    		stdout.println("Reported Issue: "+issue.getIssueName()
			    					+"\n¹Response HTTP: "+responseStatus.getStatusCode()
			    					+"\n²Response body:"
			    					+"\n" + responseAsString);
			    	} else {
			    		stdout.println("Reported Issue: "+issue.getIssueName()
			    					+"\n¹Response HTTP:  "+responseStatus.getStatusCode());
			    	}
			    } else{
			    	stderr.println("Reported Issue: "+issue.getIssueName()
	    					+"\n¹Response HTTP: "+responseStatus.getStatusCode() + "(unexpected response. Check body.)"
	    					+"\n²Response body:"
	    					+"\n" + responseAsString);
			    }
			} catch(Exception e) {
				stderr.println("Bombed out: " + e.getMessage());
				if(debug==false){callbacks.unloadExtension();}
			}
		}
	}
	
	
	
	private void setHeaders(List<String> lines) {
		String nextLine = lines.remove(0);
		List<Header> headers = new ArrayList<Header>();
		while(!PostUtils.HEADER_DELINEATOR.equals(nextLine)) {
			String headerName = StringUtils.substringBefore(nextLine,": "); //don't anticipate http changing. hardcoded this.
			String headerValue = StringUtils.substringAfter(nextLine,": ");
			Header header = new BasicHeader(headerName, headerValue);
			System.out.println(header.toString());
			headers.add(header);
			nextLine = lines.remove(0);
		} 
		if (!headers.isEmpty())
		{
			this.headers.addAll(headers);
		}
	}
	
	@Override
	public void extensionUnloaded() {stdout.println("Extension was unloaded");}
	
	public List<String> getPostFile(){return postFile;}
		
	public void setPostFile(List<String> postFile) {this.postFile = postFile;}
	
	public void setReportingUrl(String url) throws MalformedURLException {reportingUrl = new URL(url);}
	
	public void chooseConfidence() 
	{
		String confChosen = (String) JOptionPane.showInputDialog(
					null, //no parent yet. May configure this later if I can.
					"Lowest confidence level to report:",
					"Minimum Issue Confidence",
					JOptionPane.PLAIN_MESSAGE,
					null, //no icon yet. Low Prio TODO: Icon
					PostUtils.CONFIDENCE_LIST,
					PostUtils.CONFIDENCE_LIST[0]
				);
		if(confChosen == null || confChosen.isEmpty()) {return;}
		for(String ConfidenceMatch : Arrays.asList(PostUtils.CONFIDENCE_LIST)){
			if (ConfidenceMatch.contains(confChosen)){
				Confidence = confChosen; 
				return;
			}
		}
		throw new IllegalArgumentException("Confidence level chosen does not match static list. This should be impossible.");
	}
	
	public boolean checkConfidence(String confCheck) {
		for (int i=0;i<=PostUtils.CONFIDENCE_LIST.length;i++){
			//if we match the confCheck input before we match the Confidence minimum, return true.
			//Otherwise, if we hit the Confidence minimum without a confCheck match, we didn't hit the min. Return false.
			if (PostUtils.CONFIDENCE_LIST[i].equals(confCheck)){
				return true;
			}
			if (PostUtils.CONFIDENCE_LIST[i].equals(Confidence)){
				return false; 
			}
		}
		throw new IllegalArgumentException("Confidence level chosen does not match static list. This should be impossible.");
	}	
		
	private void setDebug(boolean debug, boolean unit){
		this.debug = debug;
		if (unit == true && debug == true){ //intended for initializing unit testing
			stdout = new PrintWriter(System.out);
			stderr = new PrintWriter(System.err);
			client = HttpClientBuilder.create().build();
		}
		
	}
	private void setDebug(boolean debug){
		setDebug(debug, false);
	}
	
	public static void main(String[] args){
		
		BurpExtender testExtender = new BurpExtender();
		testExtender.setDebug(true, true);
		
		List<String> testList = new ArrayList<String>();
		
		//***PASS as of 22 Feb 2014
		System.out.println("***File Read:***");
		try{
			JFileChooser fc = new JFileChooser();;
			int returnVal = fc.showOpenDialog(null);
			System.out.println("Choosing file from Open Dialog.");
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                System.out.println("Reading POST template from " + file.toPath().toAbsolutePath() + "...");
                testList.addAll(Files.readAllLines(file.toPath(), Charset.defaultCharset()));
            } else {
            	System.out.println("No template chosen. Ending...");
            	return;
            }
            
			
		}catch (Exception e) { //this try/catch pattern is horrible and will not be used in non-test cases.
			try{
				System.out.println("Reading POST template from "+Paths.get(PostUtils.FILE_PATH).toAbsolutePath()+"..."); //throw new Exception();
				testList.addAll(Files.readAllLines(Paths.get(PostUtils.FILE_PATH),
			            Charset.defaultCharset()));
				System.out.println("File Read passed.");
				/**/
				
				
			} 
		    catch (Exception ex) {
		    	System.out.println("FILE READ FAILED for "+Paths.get(PostUtils.FILE_PATH).toAbsolutePath()+". See stack trace. Resorting to hard-coded list for remaining test cases.");
		    	ex.printStackTrace();
		    	testList.add("https://www.nvisium.com"); 
		    	testList.add("Content-Type: application/x-www-form-urlencoded;");
		    	testList.add("---");
		    	testList.add("{");
				testList.add("    \"fields\": {");
				testList.add("       \"project\":");
				testList.add("       {");
				testList.add("       //This is a comment.");
				testList.add("//This is a comment at the beginning of the line.");
				testList.add("          \"key\": \"TEST\"");
				testList.add("       },");
				testList.add("       \"summary\": \"<%IssueBackground%>\",");
				testList.add("       \"description\": \"<%IssueDetail%>\",");
				testList.add("       \"issuetype\": {");
				testList.add("          \"name\": \"Bug\" //IssueType mapping will probably be sorted later.");
				testList.add("       }");
				testList.add("   }");
				testList.add("}");
		    }  
		}
		
		testExtender.chooseConfidence();
		
		try{
			testExtender.setReportingUrl(testList.remove(0));
		} catch(MalformedURLException murle) {
			System.out.println("URsL improperly formated.");
		}
		
		//***PASS as of 15 Jan 2014
		System.out.println("***setHeaders test:***");
		testExtender.setHeaders(testList);
		
		System.out.println("***Initial list:***");
		for(String line:testList){System.out.println(line);}
		
		
		
		//***PASS as of 01 Jan 2014
		System.out.println("***deComment test:***");
		
		try{
			testList = PostUtils.deComment(testList);		
			for(String line:testList){System.out.println(line);}
		} catch(Exception e) {
			System.out.println("DECOMMENT TEST FAILED. See stack trace.");
			e.printStackTrace();
		}
		
		
		//***PASS as of 02 Jan 2014
		System.out.println("***filledParams test:***");
		
		IScanIssue testIssue = new TestIScanIssueImpl();
		try {
			testList = PostUtils.fillParams(testList, testIssue);
			for(String line:testList){System.out.println(line);}
		} catch (Exception e) {
			System.err.println("FILLED PARAMS TEST FAILED. See stack trace.");
			e.printStackTrace();
		}
		
		
		//And now we try posting.
		//***PASS as of 04 Jan 2014
		testExtender.setPostFile(testList);
		try{
			testExtender.newScanIssue(testIssue);
			testExtender.stdout.flush();
			testExtender.stderr.flush();
		} catch(Exception e) {
			System.err.println("FILLED PARAMS TEST FAILED. See stack trace.");
			e.printStackTrace();
		}
		
	}
}

