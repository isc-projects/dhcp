<!--
THIS ISSUE TEMPLATE IS INTENDED ONLY FOR INTERNAL USE.

If the bug you are reporting is potentially security-related - for example,
if it involves an assertion failure or other crash in isc-dhcp that can be
triggered repeatedly - then please make sure that you make the new issue
confidential!
-->

[TOC]

## Quick Links

This is a checklist for EOL software. The main differences to the usual process are:

- No release, no release checklist, just the patch in public repo
- No affected versions determination
- The fix is optional (no for client, relay; maybe for server). If we decide to not fix it, many steps are skipped
- System tests/reproducer optional
- The T-5 period is really T-30
- No T-3/T-1 steps

[checklist_explanations]: https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations

⏩ **Each [:grey_question:][checklist_explanations] is a link to [explanations of each checklist step][checklist_explanations].** ⏪

|                    |                                                                        |
| ------------------ | ---------------------------------------------------------------------- |
| Incident Manager:  | @user (assigned SwEng person) [:grey_question:][step_incident_manager] |
| ~~Multi-vendor?~~      | NO                                                                     |
| Public Disclosure: | YYYY-MM-DD                                                             |
| CVSS Score:        | [0.0][cvss_score_url]                                                  |
| CWE:               | [CWE-NNN][cwe_category_url]                                            |
| EVN Preamble:      | [e-n-d!NNN][earliest_url]                                              |
| Security Advisory: | [p-p!NNN][press_url]                                                   |
| Zulip Topic:       | [CVE-YYYY-NNNN][zulip_url]                                             |
| Support Ticket:    | [URL]                                                                  |
| ~~Release Checklist:~~ | (none, no release planned)                                         |

[cvss_score_url]: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X&version=3.1
[cwe_category_url]: https://cwe.mitre.org/data/definitions/NNN.html
[earliest_url]: support-team/earliest-notification-drafting!NNN
[press_url]: isc-private/printing-press!NNN
[zulip_url]: https://zulip.isc.org/#narrow/channel/41-bind9-incidents/topic/XXXXX

## CVE Checklist

### ASAP

  - [ ] [:grey_question:][step_emergency]         **(SwEng)** For EOL software, determine if a fix is necessary (not for client or relay, it depends on the server)

  - [ ] [:grey_question:][step_emergency]         **(SwEng)** Consider invoking the emergency procedures
  - [ ] [:grey_question:][step_oper_notification] **(SwEng)** Consider if we need Operational Notification
  - [ ] [:grey_question:][step_zulip]             **(SwEng)** Create a dedicated Zulip Topic
  - [ ] [:grey_question:][step_respond]           **(SwEng)** Respond to the bug reporter
  - [ ] [:grey_question:][step_public_mrs]        **(SwEng)** Ensure there are no public merge requests which inadvertently disclose the issue

### Before Code Freeze (there is no code freeze)

  - [ ] [:grey_question:][step_assign_cve_id]     **(SwEng)** Assign a CVE identifier, and update the GitLab Issue with it
  - [ ] [:grey_question:][step_note_cve_info]     **(SwEng)** Determine CVSS score and CWE category, and update the GitLab Issue with them
  - [ ] [:grey_question:][step_versions_affected] **(SwEng)** Use the following as branches/versions affected: 4.4.3/latest master
  - [ ] [:grey_question:][step_advisory_mr]       **(Support)** Begin preparing the Security Advisory in printing-press
  - [ ] [:grey_question:][step_reproducer]        **(SwEng)** Prepare a private merge request for a fix (optional). A system test reproducing the problem is optional, too.
  - [ ] [:grey_question:][step_notify_support]    **(SwEng)** Notify Support when a reproducer is ready (optional)
  - [ ] [:grey_question:][step_fix]               **(SwEng)** Prepare a fix and push it as a separate commit to the merge request with the reproducer (optional)
  - [ ] [:grey_question:][step_review_fix]        **(SwEng)** Ensure the merge request with the fix is reviewed and has no outstanding discussions (if fix is needed)
  - [ ] [:grey_question:][step_review_docs]       **(Support)** Review the documentation changes introduced by the merge request with the fix
  - [ ] [:grey_question:][step_merge_fixes]       **(SwEng)** Merge the CVE fixes and reproducer when they get approved to private repo
  - [ ] [:grey_question:][step_finish_advisory]   **(Support)** Finish preparing the Security Advisory in printing-press


### At T-30

This is really the same as T-5 for other projects.

  - [ ] [:grey_question:][step_evn_send_t_5]      **(Support)** Notify eligible customers by adding a ticket to the 5-Day queue in RT with the text of the advisory (Combining the "EVN Preamble" and "Security Advisory" texts)

### At T-3

Nothing.

### At T-1

Nothing.

### On the Day of Public Disclosure

  - [ ] [:grey_question:][step_eol_public_repo]   **(SwEng)** Push the merged fix from private to public repo
  - [ ] [:grey_question:][step_eol_public_issue]  **(SwEng)** Switch the confidentiality off on the issue
  - [ ] [:grey_question:][step_bump_advisory]     **(Support)** Bump Document Version for the Security Advisory in Printing Press
  - [ ] [:grey_question:][step_publish_advisory]  **(Support)** Knowledge Base: Publish the Security Advisory as a new article
  - [ ] [:grey_question:][step_mitre]             **(QA)** Advise MITRE about the disclosed CVEs
  - [ ] [:grey_question:][step_merge_advisory]    **(QA)** Merge the Security Advisory merge request
  - [ ] [:grey_question:][step_embargo_end]       **(SwEng)** Inform original reporter (if external) that the security disclosure process is complete
  - [ ] [:grey_question:][step_evn_clear]         **(Support)** Update the tickets in the EVN queues in RT that the embargo is lifted
  - [ ] [:grey_question:][step_customers]         **(Marketing)** Ensure that a ticket has been sent in the appropriate announce queue in RT to notify customers that the release is published (as outlined in the release checklist)

[step_incident_manager]:  https://gitlab.isc.org/isc-private/bind9/-/wikis/Initial-Handling-of-(Potential)-Security-Issues
[step_emergency]:         https://gitlab.isc.org/isc-private/bind9/-/wikis/In-Case-of-Emergency
[step_oper_notification]: https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#consider-if-we-need-operational-notification
[step_zulip]:             https://gitlab.isc.org/isc-private/bind9/-/wikis/In-Case-of-Emergency#create-a-dedicated-zulip-topic
[step_respond]:           https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#respond-to-the-bug-reporter
[step_public_mrs]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#ensure-there-are-no-public-merge-requests-which-inadvertently-disclose-the-issue
[step_coordinate_cve_id]: https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#check-if-we-need-to-coordinate-with-other-vendors-an-industry-wide-cve-identifier-might-be-necessary
[step_assign_cve_id]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#assign-a-cve-identifier
[step_note_cve_info]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-this-issue-with-the-assigned-cve-identifier-the-cvss-score-and-the-cwe-category
[step_versions_affected]: https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#determine-the-range-of-product-versions-affected-including-the-subscription-edition
[step_workarounds]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#determine-whether-workarounds-for-the-problem-exist
[step_earliest_prepare]:  https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-earliest-notification-text~~ Prepare an earliest notification in https://gitlab.isc.org/support-team/earliest-notification-drafting/-/merge_requests similar to https://gitlab.isc.org/support-team/earliest-notification-drafting/-/merge_requests/94
[step_earliest_send]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-earliest-notification-ticket-in-support-portal-earliest-queue-which-will-notify-earliest-customers
[step_advisory_mr]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#create-a-merge-request-for-the-security-advisory-and-include-all-readily-available-information-in-it
[step_reproducer]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-private-merge-request-containing-a-system-test-reproducing-the-problem
[step_notify_support]:    https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#notify-support-when-a-reproducer-is-ready
[step_code_analysis]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-detailed-explanation-of-the-code-flow-triggering-the-problem
[step_fix]:               https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-a-fix-and-push-it-as-a-separate-commit-to-the-merge-request-with-the-reproducer
[step_review_fix]:        https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#ensure-the-merge-request-with-the-fix-is-reviewed-and-has-no-outstanding-discussions
[step_review_docs]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#review-the-documentation-changes-introduced-by-the-merge-request-with-the-fix
[step_backports]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-backports-of-the-merge-request-addressing-the-problem-for-all-affected-and-still-maintained-branches-of-a-given-product
[step_finish_advisory]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#finish-preparing-the-security-advisory
[step_issue_milestone]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#move-this-issue-to-its-release-milestone
[step_coordinate_check]:  https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#make-sure-other-vendors-are-able-to-release-on-the-date-that-was-previously-agreed-upon
[step_merge_fixes]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-the-cve-fixes-in-cve-identifier-order
[step_evn_releases]:      https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#prepare-evn-releases-as-outlined-in-the-release-checklist
[step_evn_links]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bind-9-only-update-the-bind--s-ticket-in-the-support-portal-with-download-links-to-the-new-versions
[step_evn_send_t_5]:      https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#notify-eligible-customers-by-adding-a-ticket-to-the-5-day-queue-in-rt-with-the-text-of-the-advisory-earliest-and-t-5
[step_preannouncement]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#send-a-pre-announcement-email-to-the-appropriate--announce-mailing-list-to-alert-users-that-the-upcoming-release-will-include-security-fixes
[step_evn_send_t_3]:      https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#notify-eligible-customers-by-adding-a-ticket-to-the-3-day-queue-in-rt-with-the-text-of-the-advisory-t-3
[step_packager_emails]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#send-notifications-to-os-packagers
[step_clearance]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#grant-qa--marketing-clearance-to-proceed-with-public-release
[step_matrix]:            https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bind-9-only-add-the-new-cves-to-the-vulnerability-matrix-in-the-knowledge-base
[step_bump_advisory]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#bump-document-version-for-the-security-advisory-in-printing-press
[step_publish_advisory]:  https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#publish-the-security-advisory-in-the-knowledge-base
[step_publish]:           https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#publish-the-releases-as-outlined-in-the-release-checklist
[step_notifications]:     https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#send-notification-emails-to-third-parties
[step_mitre]:             https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#advise-mitre-about-the-disclosed-cves
[step_merge_advisory]:    https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-the-security-advisory-merge-request
[step_embargo_end]:       https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#inform-original-reporter-if-external-that-the-security-disclosure-process-is-complete
[step_evn_clear]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#update-the-tickets-in-the-evn-queues-in-rt-that-the-embargo-is-lifted
[step_customers]:         https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#ensure-that-a-ticket-has-been-sent-in-the-appropriate-announce-queue-in-rt-to-notify-customers-that-the-release-is-published-as-outlined-in-the-release-checklist

[step_eol_public_repo]:   https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-to-public-repo
[step_eol_public_issue]:  https://gitlab.isc.org/isc-private/isc-wiki/-/wikis/Security-Incident-Handling-Checklist-Explanations#merge-to-public-repo

## Original Report

/confidential
