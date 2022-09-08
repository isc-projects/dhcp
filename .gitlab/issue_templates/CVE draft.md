---
name: CVE Advisory Draft
about: Create a draft advisory for a security vulnerability

---
:::(Internal) (This is a template for a new CVE advisory text article)
Internal notes, like this one, will give directions for using this template.  It is only rendered for logged-in users, i.e. ISC Staff.
:::
:::(Internal) (Crouching Vulnerability, Hidden Draft)
To create a new advisory text article, first create a new blank article with a non-descript subject in the Security Advisories section.  Second, mark the article as hidden and move it to the top of the list so that it can be found easily.  Third, after verifying that the article is hidden, modify the article "slug" below the title to match the CVE identifier (you should not do the redirect if prompted).  Fourth, copy and paste the entire template contents (that you're reading right now) from the template article into the new article.  Fifth, remove this note from the new article.
:::
:::(Internal) (Keep things text-only friendly)
All of the official communication about this vulnerability will use a text-only version of this article.  Since this article remains our official internal master version of the document, it will have to be converted to text multiple times by the time of the public announcement.  It is therefore critical that its content be kept "text friendly".  This is most obvious in the way that certain links are constructed.  Most links should be constructed contrary to "web best-practice" and use the full URL as their link text.  The two exceptions to this are the CVE number at the top of the article, linking to mitre.org, and the name of the Program Impacted, which may also be a link the main product page on our website.
:::
:::(Internal) (Remove only before final publication)
Unless otherwise directed, this note and all of the ones above it should only be removed after verifying that all other notes have been removed as the final step before publishing.  This is to help keep track of what has been done and still needs to be done.
Technically these "Internal Note" boxes don't need to be removed before publishing, but it's probably a good idea to do so.
:::
:::(Internal) (CVE-YYYY-NNNN)
A global search and replace should be performed updating all instances of CVE-YYYY-NNNN with the CVE identifier.  Once this step is performed remove this note.)
:::
**CVE:** [CVE-YYYY-NNNN](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-NNNN)

:::(Internal) (Document version)
The document version starts at "1.0" and remains there until the first mass disclosure, **not counting** notifications to "Earliest" customers.  After that each mass-distributed modified version needs a new version number, increasing the previous one by "0.1".  Note that this follows our software version numbering policy, rather than basic math, so that the successor to "1.9" is "1.10" and not "2.0".  Version "2.0" is reserved for the document as it exists at the time of the public announcement.  Modifications after the public announcement also get version number increases.  Each version number used needs to have an entry in the "Version History" section below.
:::
:::(Internal) (Increasing the Document Version?  Don't forget to add an entry to the Document History section)
This is *very* easy to forget.
:::
**Document version:** 1.0

:::(Internal) (Posting Date)
The posting date is the **planned** public announcement date before the public announcement and the **actual** public announcement date afterward.
:::
:::(Internal) (Date Format)
For consistency, dates should be formatted as "day-of-month month-name full-year", ```"%d %B %Y"``` in ```strftime``` format (using an ```en``` locale), for example: "20 November 2019"
:::
**Posting date:** day-of-month month-name full-year

:::(Internal) (Modify as appropriate)
This may be easy to forget on the relatively rare CVEs affecting other products.
:::
**Program impacted:** [BIND](https://www.isc.org/bind/)

:::(Internal) (Versions Affected)
For clarity, repeat the product name at the head of the version list.  This is expected to list **every** affected release version.  If we did not test certain ranges of versions then that should be noted after the list of versions known to be vulnerable.  Typically development versions are silently not mentioned unless they are part of the current development branch.  Alpha and beta versions are never mentioned unless they are a boundary between vulnerable versions and versions that are not affected.  Always includes Supported Preview Edition versions ("-S" releases) when affected, noted as being "of BIND 9 Supported Preview Edition".  When versions from the current development branch are included they are listed as being "of the BIND 9.15 development branch" (modifying the product name and branch number as appropriate).  Ranges are specified using "->" (minus greater than) for plain-text compatibility.
:::
**Versions affected:** BIND 9.0.0 -> 9.99.99.

:::(Internal) (Severity)
As per the CVSS scoring.  Note that per current ISC standards we use the severity from the scoring with Temporal modifiers, but when the information is published to Mitre only the base score is used.  This may result in there being different severities listed, which may lead to questions, but the important thing here is that this severity agrees with the severity of the vector given later in the advisory text.
:::
**Severity:** Medium

:::(Internal) (Exploitable)
This describes the "Network" portion of the CVSS vector, and may also include specific caveats to the CVSS designation.  An example of an extended description is "Remotely, if an attacker can trigger a zone transfer".
:::
**Exploitable:** Remotely

:::(Internal) (Description)
A description of the vulnerability that is as concise as possible while maintaining both clarity and technical correctness.  Should contain the minimum detail necessary.
:::
**Description:**

The software does something wrong.

:::(Internal) (Impact)
This is result of the vulnerability being triggered.  While some vulnerabilities may be triggerable accidentally and unknown to the triggering person, this is always written as if the triggering person were a hostile attacker.  It should focus on what the attacker can accomplish that they otherwise ought not be able to.
:::
**Impact:** 

A meanie can do bad things with it.

:::(Internal) (Be sure to update this when the CVSS vector changes)
It is easy to forget.
:::
**CVSS Score:** 6.5

:::(Internal) (CVSS Vector)
Usually provided by engineering.  Per our current standards includes the temporal scoring section.
:::
:::(Internal) (When this changes be sure to update this text along with the link and link text below)
It is easy to forget.
:::
**CVSS Vector:** CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X/E:X/RL:X/RC:X

:::(Internal) (When updating this, be very, very, careful in checking that the vector string above matches **both** the link text and the link below.)
This is ***very*** easy to forget.
:::
For more information on the Common Vulnerability Scoring System and to obtain your specific environmental score please visit: [https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X/E:X/RL:X/RC:X&version=3.1](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X/E:X/RL:X/RC:X&version=3.1).

:::(Internal) (Workarounds)
Our vulnerabilities don't always have workarounds, but when they do we describe them here.
:::
**Workarounds:** 

No workarounds known.

**Active exploits:** 

We are not aware of any active exploits.

:::(Internal) (Solution)
Most of the time the only solution is to upgrade, but if there are any other solutions they should be listed here too.
:::
**Solution:** 

Upgrade to the patched release most closely related to your current version of BIND:

 *  BIND 9.ESV
 *  BIND 9.STABLE
 *  BIND 9.DEV

BIND Supported Preview Edition is a special feature preview branch of BIND provided to eligible ISC support customers.

* BIND 9.ESV-S

:::(Internal) (Acknowledgments)
This optional section should be populated with a brief note of thanks to the submitter if and only if they have indicated that they would like to be publicly credited for the discovery.  It is the incident manager's responsibility to ensure that they are asked in a timely fashion.
:::

**Acknowledgments:** ISC would like to thank Phineas Q. Troublemaker for discovering and reporting this issue.

:::(Internal) (Document Revision History)
The format for this list is:
version description, day-of-month en-month-name full-year
:::
**Document revision history:** 

1.0 Early Notification, day-of-month en-month-name full-year

:::(Internal) (Related documents)
An example related document might be another KB article containing a FAQ or an explanation in greater detail.
:::
**Related documents:**

See our [BIND 9 Security Vulnerability Matrix](https://kb.isc.org/docs/aa-00913) for a complete listing of security vulnerabilities and versions affected.

:::(Internal) (Begin Boilerplate)
Aside from the permanent link back to this article, nothing beyond this point should need changing on a per-CVE basis.  And you already updated the document self-link, with the global search-and-replace, right?
:::
**Do you still have questions?** Questions regarding this advisory should go to [security-officer@isc.org](mailto:security-officer@isc.org). *To report a new issue, please encrypt your message using security-officer@isc.org's PGP key which can be found here: [https://www.isc.org/pgpkey/](https://www.isc.org/pgpkey/). If you are unable to use encrypted email, you may also report new issues at: [https://www.isc.org/reportbug/](https://www.isc.org/reportbug/).* 

**Note:** 

ISC patches only currently supported versions. When possible we indicate EOL versions affected.  (For current information on which versions are actively supported, please see [https://www.isc.org/download/](https://www.isc.org/download/).)

**ISC Security Vulnerability Disclosure Policy:** 

Details of our current security advisory policy and practice can be found in the ISC Software Defect and Security Vulnerability Disclosure Policy at [https://kb.isc.org/docs/aa-00861](https://kb.isc.org/docs/aa-00861).

:::(Internal) (Document self-link)
Remove this note after updating the CVE number in both the link text and the link, itself.
:::
The Knowledgebase article [https://kb.isc.org/docs/cve-YYYY-NNNN](https://kb.isc.org/docs/cve-YYYY-NNNN) is the complete and official security advisory document.

**Legal Disclaimer:** 

Internet Systems Consortium (ISC) is providing this notice on an "AS IS" basis. No warranty or guarantee of any kind is expressed in this notice and none should be implied. ISC expressly excludes and disclaims any warranties regarding this notice or materials referred to in this notice, including, without limitation, any implied warranty of merchantability, fitness for a particular purpose, absence of hidden defects, or of non-infringement. Your use or reliance on this notice or materials referred to in this notice is at your own risk. ISC may change this notice at any time. A stand-alone copy or paraphrase of the text of this document that omits the document URL is an uncontrolled copy. Uncontrolled copies may lack important information, be out of date, or contain factual errors.
