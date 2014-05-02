# Burp Issue Poster

This Burp Extension is intended to post to a service the details of an 
issue found either by active or passive scanning. The post request is 
written as a template and substitutes the contents of the issue into a 
post body which is pre-formatted per the requirements of the reporting 
application's own API.

In other words: you format the post you wish to send to the service,
and this extension fills in the details based on the attributes you 
wish to include. You can then post any discovered issues to your 
reporting application of choice rather than fiddle with reports from
Burp Suite directly.

This is an alpha-quality extension targeted at technically minded users. 
Aside from a few GUI elements, there are more user-friendly changes 
still in development. The primary goal here is to release what I have
so that others can look at it and tear into it. 

If you use this in the course of your assessments, **please protect
your template.** At least in its current state, you'll have to include
authentication data as a header item. A best case scenario would be to
create a service account and to use a session identifier for that 
account rather than constantly posting credentials, but this may not
necessarily matter in your environment.


## Usage:
1. Before beginning, ensure that you've written a post template 
adequate for your needs. For more information on this, please see the 
bip-post text files for examples on formatting, and see the section 
below titled "Template" for guidance on what to include.
1. Narrow your Burp Scanner scope. Without narrowing your scope, all
issues will be submitted. You will be prompted upon loading BIP to
verify whether you have adequately narrowed your scope.
2. Once you confirm that your scope is narrowed per your needs, BIP
will prompt you for the file you wish to use as your posting template.
3. Choose your desired minimum confidence.
4. Once BIP is loaded, you may configure Burp Proxy if you have not yet
done so.

That's it!

## Template
A number of example templates are included under the root of this project with
the prefix "bip-post" in the name. The template itself is straightforward:
* The first line is the full path to the service endpoint receiving the issues.
It is preferred that you post to an https endpoint, but this depends on your
implementation. 
* Every line thereafter is an individual header. Your authentication header 
should go here. *Noted Earlier:* Depending on your environment, it may be 
better to create a service account with extremely limited capabilities rather 
than using your own account for the reporting service. 
* Separating the post body is three dashes on their own standalone line.
Below the three dashes is the content of the post body, which should be
formatted based on what you intend to submit to the receiving service.
You should consult the documentation for your desired service, but the
provided example should function for a basic JIRA implementation. For all
available verbs, see "Available Issue Items" below.

When configuring the template to include elements of the IScanIssue
object, consider whether what Burp includes should be HTML-escaped.
For instance, IssueBackground should be escaped unless the service to which
you're posting deliberately allows unescaped HTML. Note that escaped HTML will
most likely not render within your desired reporting tool.

## Available Issue Items:
The following Issue items are available to you in reporting:
* Confidence
* HttpService
* IssueBackground
* IssueDetail
* IssueName
* RemediationBackground
* RemediationDetail
* Severity
* Url

Although you can report the IssueType, IssueTypes are reported as integers
which can then be mapped to specific names. For the full map, please visit
http://portswigger.net/burp/help/scanner_issuetypes.html

## TODO
There are a number of items which are outstanding and are considered for future
implementation:
* **Implementing HttpMessages and IssueType as a reportable item.** 
Currently, the HttpMessages attribute is not supported. The technical reason: 
this is a limitation of the fact that the toString() method called against the 
object returned by getHttpMessages() is actually called against an array, not 
an individual HttpMessage. This can be implemented later if the feature is 
desired.
Only partially supported is the IssueType. The mappings between the Issuetype 
IDs isn’t there yet, so if you choose to report the IssueType, you’ll just end 
up grabbing a number. The correlations can all be found under the relevant 
documentation at portswigger.net
* **Implementing a tab for configuring the extension with less manual effort.**
As of right now, much of the configuration is restricted to what can be 
accomplished in the template file. A tab with the most common options can 
also allow a user to create a template which can then be passed around. 
However, the message body will still need to be written by the user.
* **Retaining authentication information outside the template.**
Currently, authentication information needs to be included in the template as 
either an authentication header or a cookie (also baked into the request as a 
header item). A future change would allow the authentication data to be added 
during runtime to the list of headers without having to be pulled from the 
template.
* **Other non-issue items for reporting.**
For instance: an epoch timestamp, I haven't quite decided on the details 
surrounding how I'll implement this.
* **Refinement.**
A lot of what you're seeing here was produced at speed rather than through a
traditional and traditionally rigorous development and review process. So, 
refining the code you see here is a ToDo item.

# Compiling
You should include your version of Burp Suite Professional within the lib 
directory. Without listing Burp Suite as a dependency, this won't build.

# License

The code written for this extension is covered by the BSD license, below. This 
license does not supercede any licenses for any dependencies used by this 
extension.

> Copyright (c) 2014, Bryant Zadegan.
> All rights reserved.
> 
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
> 
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
> 
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
> 
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
> 
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.