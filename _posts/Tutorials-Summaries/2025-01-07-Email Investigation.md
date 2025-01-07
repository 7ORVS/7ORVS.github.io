---
title: "Email Investigation"
classes: wide
header:
  teaser: /assets/images/site-images/Email.jpg
ribbon: Black
description: "In this blog I'm talking about Email Investigation"
categories:
  - Tutorials Summaries
toc: true
---



In this blog, I will explore email threats, including understanding potential dangers from emails, understanding emails, its structure and email headers, identifying suspicious elements, and addressing them effectively.

I'll relay for this blog on:
- TCM soc 101 course (Phishing Analysis Module )
- Effective Threat Investigation for SOC analysts Book (Ch.1, Ch.2) By Mostafa Yehia 
- [SOC Investigation/ How to investigate Cyber Cases/ Network Forensics and log Analysis](https://www.youtube.com/playlist?list=PLdUDP-atVHBoDae43tcUZnW1YsjoPJRvP) (Video 3, 6)
- Articles in References section  
# Phishing 
According to this [article](https://www.ibm.com/think/topics/phishing), phishing is a type of cyber attacks when the attacker attacks human errors and it's form of social engineering.
By using this technique, the attacker exploit the trust by pretending to be someone the victim trusts to trick him into sharing sensitive data, downloading malware or otherwise exposing themselves to cyber-crime by using emails, text messages  or websites.

Because of our modern life and the role of technology in our lifestyle, emails have become the traditional way to communicate with each other especially in working stuff. So, attackers finds that they can uses their techniques to achieve the initial access to the target by crafting emails that mimic reputable businesses like banks or online retailers to increase the likelihood that recipients will engage with them. By using logos, branding, and spoofed email addresses, they make phishing emails appear authentic, sometimes even replicating real messages with malicious modifications. These emails often have urgent or emotionally charged subject lines, such as "Problem with your order," to prompt quick action.

The email content typically instructs recipients to take actions like clicking a link to "update your profile," which leads to fake websites designed to steal login credentials or install malware and maybe the malware is the content itself like malicious PDFs or Docs files that contain an malicious code or macros to drop a malware in victim machine  . Scammers often align their campaigns with events like holidays or sales, such as Amazon's Prime Day, exploiting heightened activity and lower vigilance during these times.

# Understanding Email 

To catch the abnormals you must know what the normal looks like and the normal flow and behavior of things, so, in this part I'll talk about email protocols, key components of email flow process and the email flow itself.
## Email Protocols:

Emailing process uses 4 main protocols:

- **SMTP** : Simple Mail Transfer mechanism (SMTP) is a mechanism for exchanging email messages between servers. It is an essential component of the email communication process and operates at the application layer of the TCP/IP protocol stack a. SMTP is a protocol for transmitting and receiving email messages.
	- port : 25,587

- **POP3** : Post Office Protocol is used to retrieve email for a single client. POP3 version is the current version of POP used. It is an application layer protocol. It allows to access mail offline and thus, needs less internet time. To access the message it has to be downloaded. POP allows only a single mailbox to be created on the mail server. 
	- port : 110

- **IMAP** : Internet Message Access Protocol is used to retrieve mails for multiple clients. There are several IMAP versions: IMAP, IMAP2, IMAP3, IMAP4, etc. IMAP is an application layer protocol. IMAP allows to access email without downloading them and also supports email download. The emails are maintained by the remote server. It enables all email operations such as creating, manipulating, delete the email without reading it. IMAP allows you to search emails. It allows multiple mailboxes to be created on multiple mail servers and allows concurrent access.
	- port : 143

- **MIME** : Multipurpose Internet Mail Extension Protocol is an additional email protocol that allows non-ASCII data to be sent through SMTP. It allows users to send and receive different types of data like audio, images, videos and other application programs on the Internet. It allows to send multiple attachments with single message. It allows to send message of unlimited length.

I'll put articles for more information in References section.

## Key Components of email flow:

Before describing the email flow you may need to know the key components of this process and you can find a details about it on Ch.2 on "Effective Threat Investigation for SOC analysts " Book (pg. 27 & 28)

## Email Flow:

Now let me explain the email flow step by step.

- The sender writes an email using **MUA**  

- The MUA sends the email to MSA and MSA will authenticate the sender and verifies the email structure then push it to MTA

- MTA receives the email from MSA and determines the recipient’s domain (e.g., abc.com) from the email address then performs a **DNS Lookup** to find **MX record** of the recipient's domain. The MX record is typically list of the mail servers for the recipient's domain.

- MTA servers efficiently routes the email to the appropriate MX server, which is responsible for receiving emails sent to the recipient’s domain.

- Finally, the MX server forwarded the email to the recipient’s MDA server, which allowed the authenticated end user to view the message in his mailbox via his MUA


We need to know that every hop in this process adding a header to the email message header that contains at least the email server’s hostname, server IP, and date and time of email processing.

## Email Authentication Methods

To avoid spoofing domain owners define a records and rules to be checked by a receiving email server to decided to either deliver the mail to the receiver mail's box or not.
In email we have 3 authentication protocols.
I'll talk about each one in brief but you will find a detailed information in main sources of this blog and also in References section.

- SPF (Sender Policy Framework): this protocol works by allowing the owner of a domain to specify which mail servers are authorized to send emails on behalf of their domain. So, the domain owner creates a SPF record in DNS which contains a list of IPs of authorized mail servers for the domain and the receiving mail server will compare the sender IP with these IPs in the SPF record to decide either passing the mail or dropping it.

- DKIM (DomainKeys Identified Mail): this protocol ensures that the email’s content has not been tampered with during transit and verifies the sender's authenticity by creating a digital signature by hashing and encrypt the email body and some of header fields with a private key and publishing the public key in sender domain's DNS records, so, when the receiver server get the mail it will use the public key to verify the signature.


- DMARC (Domain-Based Message Authentication, Reporting, and Conformance): this protocol works with SPF and DKIM to protect domains from email spoofing, phishing, and other fraud attempts. By defining a policy by a domain owner that specifying how to handle emails that fail SPF or DKIM checks. Based on the policy, the receiving mail server decides what to do with messages that fail the checks. It also sends a report to the domain owner with authentication details and potential abuses. 
# Email Header 

Email header constructed by every job that email passed from it and the metadata about the email, it's hidden by default from the normal user but for investigator it contains a lot of valuable details that helps you to analyze deeply the email journey and discover any threats like spoofing
You can identify email sender, sender IP, passed hops, email subject, email recipient, email timestamps, and email authentication results. Additionally, to be able to identify the presence of email spoofing.

**Note**: Keep in your mind that the header is added in a reverse order so the most top information is the most closest to the receiver.

The key components of the header are:
- **From**: The sender's email address. (This field can be spoofed by attacker or changed by the email sender)
- **To**: The recipient's email address.
- **Subject**: The subject line of the email.
- **Date**: The timestamp when the email was sent.
- **Message-ID**: A unique identifier assigned to the email by the sender’s mail server.
- **MIME-Version**: Describes the format of the email (e.g., text, HTML, attachments).
- **Content-Type**: Indicates the type of content in the email, such as plain text, HTML, or multipart (for emails with attachments).
- **Received**: 
	- A list of all servers the email passed through, showing the path from sender to recipient.
	- Each **Received** line provides the server's IP address, domain name, and timestamp.
	- Keep in mind the reverse order: The most top **Received** is the closest to the receiver
	- Typical format:
		- Received: from [sender_server] by [receiving_server] with [protocol]; [timestamp]
	- Example: 
		- Received: from smtp.sender.com (192.0.2.1) by mail.recipient.com (198.51.100.1) with SMTP; Tue, 5 Jan 2025 10:23:45 -0500
- **Reply-To**: Specifies the address where replies should be sent.
- **Return-Path**: Specifies the email address where bounce messages (e.g., undeliverable email notices) should be sent.
- **Authentication Results**: Shows the results of SPF, DKIM, and DMARC authentication checks.

You may also find a **X-Headers** which are non-standard headers included in an email by email servers, clients, or applications to provide additional information that is not part of the standard email header fields. These headers typically begin with "X-" to distinguish them from standard headers and can vary widely depending on their purpose and the system that generated them. 

Here's some of popular used X-Headers:

- **X-Originating-IP**:
    - Displays the IP address of the original sender.
    - Example: `X-Originating-IP: [192.0.2.1]`.
    - Helps trace the origin of the email, especially in cases of spam or phishing.
- **X-Mailer**:
    - Indicates the email client or application used to send the email.
    - Example: `X-Mailer: Microsoft Outlook 16.0`.
    - Useful for identifying the sender’s email software.
- **X-Spam-Status**:
    - Shows whether the email was flagged as spam by the receiving server's spam filter.
    - Example: `X-Spam-Status: Yes`.
    - Helps in analyzing why an email was categorized as spam.
- **X-Spam-Score**:
    - Provides a numerical score based on spam-detection algorithms.
    - Example: `X-Spam-Score: 5.6`.
    - The higher the score, the more likely the email is spam.

Understanding the anatomy and the structure of email header will help you as an analyst during investigation and from this information you can catch spoofing and block it before harming your organization.

# Email Content Analysis

Attacker being more creative day by day and they can bypassing the prevention mechanism and use normal trusted infrastructure so, the header analysis may get non-malicious results but actually the suspicious things stands in the email content like a malicious URL, document, malware in a compressed shape or even usual words and behavior that indicates that phishing occurred. Email content analysis is divided into these aspects:

- Subject Line Analysis: with email subject we can notice an attempts to play on user emotions like 
	- Urgent and threatening statements/words: "urgent," "action required," "click here", "Your account will be suspended", "Unauthorized access to your account", "Action Required: Update your password now!"
	- Too Good to be true promises : "Congratulations, you’ve won!", "Get a $500 gift card now!"
	And the best practice to avoid this kind of threats is to educate users and improve security awareness 
	
- Body Text Analysis: Also in this part the attacker will play on user emotions so, you need to aware users in the organization about how to recognize the phishing attempts like:
	- mail with generic greeting: Usually phishing mail is generated automatically and spread for many victims so, in most cases you will find a generic language expression which may be suspicious especially if the spoofed brand use a specific language in regular.  
	- requesting suspicious requests like sensitive information: I think in most cases the bank will not ask for your credentials to give a 500k $   
	- poor grammar and spelling: some attacker may misspell some words to avoid words filtering.

- Link Analysis: If you find a link inside the email content:
	- Ensure that the destination is legal: If the email from Microsoft why the link direct you "theartActor.mal" ?
	- If you find a short link make sure to unshort it because it can hide malicious destinations. 
	- Be careful for misspelling ("paypa1.com" instead of "paypal.com")
	- Scan the link in any threat intel feed to check if it marked as malicious or not

- Attachment Analysis: scan the attachment in any sandbox solution to check if it malicious or not and extract the IOCs.


# Investigation suspicious email

In the end of this blog I want to get a hands dirty with a suspicious email sample to see all the information we got and try to apply it in a real world scenario. I searched for a real malicious sample but I didn't find one so, I found a challenge on [https://blueteamlabs.online/](https://blueteamlabs.online/) that called [The Planetp's Prestige](https://blueteamlabs.online/home/challenge/the-planets-prestige-e5beb8e545) and it's a email file need to be analyzed.
I'll but in References section an article for an analysis for a real malicious email to get more information.

The file is an `.eml` file called **A Hope to CoCanDa**.
After opening the file in VSCode you will see the email header and its fields

![](/assets/images/tutorials-summaries/Email/Challenge_Header.png)


So, now we want to take a look for certain information:
- Sender email
- Sender Domain
- Sender Ip
- Receiver email
- Replay-To email
- Authentication result
- URL (if found)
- Attachments(if found)

Sender email can be found in **From** field, in our case the sender email is 
```
billjobs@microapple.com
```

Check the sender email spelling carefully if it from a popular vendor 

sender domain is : 
```
microapple.com
```

You can check the reputation for domain on [https://mxtoolbox.com/](https://mxtoolbox.com/) 

Sender ip is located in most button **Received** field, in our case the sender ip is:
```
93.99.104.210
```
Also you can check for the reputation on mxtoolbox or any threat intelligence feed.

Receiver email in our case is :
```
themajoronearth@gmail.com
```

Replay-To email can be an indicator of spoofing, if I send an email to you it makes sense that I want to receive your replay. So, check it will and in our case it's different from sender email.
```
negeja3921@pashter.com
```

you can also check the reputation of the domain.

Authentication result in our case telling us that **SPF** check is fail and the reason is:

```
google.com: domain of billjobs@microapple.com does not designate 93.99.104.210 as permitted sender
```

So, google tells us that it searching for SPF list of billjobs@microapple[.]com to see if the sender IP on it and it didn't find it so, the email is typically spoofed by negeja3921@pashter[.]com.


Inside the email content we will find that the subject is "A Hope to CoCanDa" which doesn't indicate any suspicious and the content type is mixed between "text/plain" and "application/pdf" and both of them base64 encoded, so, we can decode them and scan the pdf file in VirusTotal or any sandbox to check the behavoir.



At the end of this blog I encourage you to read more about [Phishing](https://attack.mitre.org/techniques/T1566/) in MITRE ATT&CK® to learn more techniques and detection methodologies and mitigations.

See you in next topic.


# References:  

- Phishing: https://www.ibm.com/think/topics/phishing
- email protocols: https://www.geeksforgeeks.org/email-protocols/
- smtp : https://www.geeksforgeeks.org/simple-mail-transfer-protocol-smtp/
- imap: https://www.geeksforgeeks.org/internet-message-access-protocol-imap/
- pop3: https://www.geeksforgeeks.org/pop-full-form/
- SPF: https://www.proofpoint.com/us/threat-reference/spf
- DKIM: https://www.mimecast.com/content/dkim/
- DMARC: https://dmarc.org/
- Email Header: https://mailtrap.io/blog/email-headers/
- Analyzing malicious Email Files Blog:  https://blog.joshlemon.com.au/analysing-malicious-email-files-d85d8ff76a91
- [How to Analyze Email Headers and How Spoofed Email Works video from "John Hubbard"](https://www.youtube.com/watch?v=reRzWHUwI80)