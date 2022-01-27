---
name: a.b.c release checklist
about: Create a new issue using this checklist for each release.
---

# ISC-DHCP Release Checklist


1. Check Jenkins results:
  1. [ ] Check Jenkins [tarball](https://jenkins.aws.isc.org/view/isc-dhcp-dev/job/dhcp-dev/job/dhcp-tarball/) job for failures
  1. [ ] Check Jenkins [unit tests](https://jenkins.aws.isc.org/view/isc-dhcp-dev/job/dhcp-dev/job/tarball-system-tests/) job for failures
  1. [ ] Check Jenkins [system tests](https://jenkins.aws.isc.org/view/isc-dhcp-dev/job/dhcp-dev/job/tarball-system-tests/) job for failures
  1. [ ] If needed use those jobs to run tests against any branch

1. Tarball preparation:
  1. [ ] If this is release of final version please check sanity check ticket of previous release and make sure all comments are addressed
  1. [ ] Make sure that Release Notes are written and reviewed before sanity checks, changes in Release Notes require tarball respin!
  1. [ ] bump up version in configure.ac
  1. [ ] change copy rights string that is printed on startup for each of the applications in `server/dhcpd.c`
  1. [ ] change copy rights string that is printed on startup for each of the applicationsdate in `client/dhclient.c`
  1. [ ] change copy rights string that is printed on startup for each of the applicationsdate in `relay/dhcrelay.c`
  1. [ ] check the date in LICENSE
  1. [ ] check README file (including installation details)
  1. [ ] update copyrigths in all touched files using simple script in [qa-dhcp](https://gitlab.isc.org/isc-private/qa-dhcp/-/tree/master/dhcp/scripts).
  1. [ ] commit changes to repo
1. aclocal/autoheader/automake/autoconf
  1. [ ] login to docs.isc.org
  1. [ ] checkout release branch (it's important to have configure.ac change done before)
  1. [ ] regenerate makefiles `aclocal && autoheader && automake && autoconf`
  1. [ ] review and push changes
1. Build tarball
  1. [ ] go to [tarball](https://jenkins.aws.isc.org/view/isc-dhcp-dev/job/dhcp-dev/job/dhcp-tarball/) > Build with Parameters, in field `dhcpBranch` put in release branch and run job, this will build release tarball and save it as artifact of the job
  1. [ ] wait for other jobs to finish testing (unit-tests and system-tests) and check their results
  1. [ ] before tarball will be deemed as ready to release it will be `release candidate`. Each consecutive respin will have it's own name starting from `-rc1`
  1. [ ] prepare directory for current release at repo.isc.org with correct prefix for release candidate e.g. `/data/shared/sweng/dhcp/releases/4.4.3b1.rc1`
  1. [ ] upload tarball and release notes (even if release notes are included into tarball, it should be also in separate file) to created directory for sanity checks
1. Sanity Checks
  1. [ ] open a ticket in dhcp repo called `release X.Y.Z-rcX sanity checks` and put there location of release tarball and it's sha256 sum
  1. [ ] wait for team input about new tarball, if respin is needed go back to `Build tarball` point also increasing release candidate number
  1. [ ] if tarball is accepted create a tag of this version on a last commit in release branch
  1. [ ] move tarball and release notes to non release candidate location (e.g. moving from /data/shared/sweng/dhcp/releases/4.3.2b1.rc1 to /data/shared/sweng/dhcp/releases/4.3.2b1)
  1. [ ] make sure that new release directory allow group write e.g. `chmod 665 /data/shared/sweng/dhcp/releases/4.3.2b1`
  1. [ ] open tickets to address issues mentioned in sanity checks IF those were not already fixed and close sanity check ticket
1. Signing and notification
  1. [ ] it's time to [open a signing ticket](https://gitlab.isc.org/isc-private/signing/-/issues) that include location and sha256 of the tarball
  1. [ ] notify support about readiness of release, at this point QA and dev team work is done
1. Releasing tarball
- [ ] ***(Support)*** Wait for clearance from Security Officer to proceed with the public release (if applicable).
 - [ ] ***(Support)*** Wait for the signing ticket from the release engineer.
 - [ ] ***(Support)*** Confirm that the tarballs have the checksums mentioned on the signing ticket.
 - [ ] ***(Support)*** Sign the tarballs.
 - [ ] ***(Support)*** Upload signature files to repo.isc.org.
 - [ ] ***(Support)*** Place tarballs in public location on FTP site.
 - [ ] ***(Support)*** Publish links to downloads on ISC website.
 - [ ] ***(Support)*** Write release email to *dhcp-announce*.
 - [ ] ***(Support)*** Write email to *dhcp-users* (if a major release).
 - [ ] ***(Support)*** Send eligible customers updated links to the Subscription software FTP site.
 - [ ] ***(Support)*** Update tickets in case of waiting for support customers.
 - [ ] ***(Marketing)*** Announce on social media.
 - [ ] ***(Marketing)*** Write blog article (if a major release).
 - [ ] ***(Marketing)*** Translate the man pages, reformat and upload to the DHCP documentation pages in the KB.



[checklist source](https://wiki.isc.org/bin/view/Main/HowToReleaseDHCP)
