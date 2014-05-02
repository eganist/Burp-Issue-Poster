package burp.utils;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.commons.lang3.StringEscapeUtils;

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

public class PostUtils {

	public static final String FILE_PATH = "bip-post.txt"; //TODO: not needed now that the open dialog is in.
	public static final String HEADER_DELINEATOR = "---";
	public static final String COMMENT_KEY = "//"; 
	
	/* The purpose of these items is to parse out the use of tokens within the code which can be substituted
	 * for the content of the IScanIssue objects. The type of flag used determines whether or not to escape
	 * the content being delivered to the receiving service, thereby keeping the receiving service from 
	 * dropping the POST as an injection attempt. The only downside to this approach is that the html isn't 
	 * rendered, so one future TODO item would be to map the Burp HTML to the equivalent tags in the receiving
	 * service/platform. 
	 */
	public static final String VAR_OPEN_KEY = "<%"; //syntax borrowed from .net code nuggets
	public static final String VAR_CLOSE_KEY = "%>";
	public static final char VAR_RAW_FLAG = '='; //pair with VAR_OPEN_KEY, i.e. <%: or <%= 
	public static final char VAR_ESC_FLAG = ':';
	
	public static final String[] CONFIDENCE_LIST = {"Certain", "Firm", "Tentative"};
	
	private PostUtils(){}
	
	public static boolean checkSuccess(int statusCode){ 
		/*This can be customized if you need to, and should definitely be customized if these
		 *status codes don't line up with your expectations or if the platform you're using
		 *explicitly differs from these.
		 */
		switch (statusCode){
		case 200:
		case 201:
		case 202: 
		case 203: 
		case 204:
		case 205: return true;
		default: return false;
		}
		
	}
	
	public static String convertListToString(List<String> list){
		StringBuffer listAsString = new StringBuffer();
		String newLine = System.getProperty("line.separator");
		for(String line:list){
			listAsString.append(line);
			listAsString.append(newLine);
		}
		return listAsString.toString();
	}
	
	/* This method accomplishes two things in the course of building an uncommented list of lines from 
	 * the input into the method:
	 * 1) Only include lines which are not exclusively comments. (This logic is not immediately apparent)
	 * 2) Only include the content before the beginning of a mid-line comment.
	 */
	public static List<String> deComment(List<String> lines) {
		ArrayList<String> deCommentedLines = new ArrayList<String>();
		for(String line:lines){
			if(line.indexOf(COMMENT_KEY) != 0){
				//in other words, only add lines which don't start with the comment key.
				deCommentedLines.add(StringUtils.substringBefore(line,COMMENT_KEY));
			}
		}
		return deCommentedLines;
	}
	
	public static List<String> fillParams(List<String> lines, IScanIssue issue) throws Exception{
			
		ArrayList<String> filledLines = new ArrayList<String>();
		Map<String,String> issueValues = new HashMap<String,String>();
		
		String flaglessKey = null;
		String currentValue = null;
		//grab all keys in the input and replace them with values from the relevant IScanIssue getters.
		//used Reflection here to save time with repetitive mapping. Eventually may adapt this for other beans.
		
		for(String line:lines){
			try{
				String[] keysArray = StringUtils.substringsBetween(line,VAR_OPEN_KEY,VAR_CLOSE_KEY);
				if(keysArray != null){
					for(String key : Arrays.asList(keysArray)){
						flaglessKey = key.substring(1);
						
						//doEscape is assumed to be true. If the flag is VAR_RAW_FLAG, set to false.
						//Went with a switch here in case other flags are added later on.
						Boolean doEscape = true;
						switch(key.charAt(0)){ //check for raw or escape flag
						
							case VAR_RAW_FLAG: doEscape = false;
							
							case VAR_ESC_FLAG: 
								Method method = issue.getClass().getMethod("get"+flaglessKey); //not hitting anything other than getters.
								Object result = method.invoke(issue);
								if (result != null) //Burp Extender API specifies the potential for null returns.
								{
									if(doEscape == true) {
										//<%:IssueName%> should resolve to issue.getIssueName()
										currentValue = selectiveEscape(result.toString()); 
									} else {
										currentValue = result.toString();
									}
								} else {currentValue = flaglessKey + " contains no further information.";}
								//put e.g. ":IssueName", "{issue name stuffs}" into the hashmap. Flag is needed for substitution.
								issueValues.put(key,currentValue); 
								
							default: flaglessKey = null; //cleanup.
						}
					}
				}
			} catch(NoSuchMethodException nsme) {
				throw new NoSuchMethodException("Token "+flaglessKey+" failed to resolve to a method.");
				
			} catch(Exception e) {
				throw new Exception("Error thrown in fillParams reflection loop.", e);
			}
			
		}
		
		for(String line:lines){	
			StrSubstitutor sub = new StrSubstitutor(issueValues, VAR_OPEN_KEY,VAR_CLOSE_KEY);
			String renderedLine = sub.replace(line);
			filledLines.add(renderedLine);
		}
		return filledLines;
		
	}
	
	public static String selectiveEscape(String input) {
		
		/*TODO: implement selectiveEscape to work by allowing certain characters/tage/etc
		 * to be escaped from the selectiveEscape method. This is intended to allow us to
		 * instead replace tags with other things, e.g. <b>Test</b> with *Test* for Jira. 
		 */
		String escapedStr = StringEscapeUtils.escapeHtml4(input);
		return escapedStr;
	}
	
	
}
