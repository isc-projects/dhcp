# Kea Contributor's Guide

So you found a bug in Kea or plan to develop an extension and want to send us a patch? Great! This
page will explain how to contribute your changes smoothly.

## Writing a patch

Before you start working on a patch or a new feature, it is a good idea to discuss it first with
DHCP developers. You can post your questions to the [dhcp-workers](https://lists.isc.org/mailman/listinfo/dhcp-workers)
or [dhcp-users](https://lists.isc.org/mailman/listinfo/dhcp-users) mailing lists. The kea-users is
intended for users who are not interested in the internal workings or development details: it is
OK to ask for feedback regarding new design or the best proposed solution to a certain problem.
This is the best place to get user's feedback. The internal details, questions about the code and
its internals are better asked on dhcp-workers. The dhcp-workers is a very low traffic list.

OK, so you have written a patch? Great! Before you submit it, make sure that your code compiles.
This may seem obvious, but there's more to it. You have surely checked that it compiles on your
system, but ISC DHCP is a portable software. Besides Linux, it is compiled and used on relatively
uncommon systems like OpenBSD. Will your code compile and work there? What about endianness? It is
likely that you used a regular x86 architecture machine to write your patch, but the software is
expected to run on many other architectures. For a complete list of systems we build on, you may
take a look at the [Jenkins build farm report](https://jenkins.isc.org/view/Kea_BuildFarm/).

## Running unit-tests

One of the ground rules in all ISC projects is that every piece of code has to be tested. For newer
projects, such as Kea, we require unit-test for almost every line of code. For older code, such as
ISC DHCP, that was not developed with testability in mind, it's unfortunately impractical to require
extensive unit-tests. Having said that, please think thoroughly if there is any way to develop
unit-tests. The long term goal is to improve the situation.

Building ISC DHCP code from the repository is slightly different than the release tarballs. One
major difference is that it does not have BIND source bundled inside and those have to be
downloaded separately. Fortunately, there's an easy to use script for that:

```bash
sh util/bind.sh v4_4
./configure --with-atf
make
```

Make sure you have ATF (Automated Test Framework) installed in your system. To run the unit-tests,
simply run:

```bash
make check
```

If you happen to add new files or have modified any Makefile.am files, it is also a good idea to
check if you haven't broken the distribution process:

```bash
make distcheck
```

There are other useful switches which can be passed to configure. A complete list of all switches
can be obtained with the command:

```bash
./configure --help
```

## Create an issue

Since you want to change something in ISC DHCP, there's a problem, deficiency or a missing feature.
Quite often it is not clear why specific change is being made. The best way to explain it is to
[create an issue here](https://gitlab.isc.org/isc-projects/dhcp/issues/new). We prefer the original
submitter fill them as he or she has the best understanding of the purpose of the change and may
have any extra information, e.g. "this patch fixes compilation issue on FreeBSD 10.1". If there there
is no MR and no gitlab issue, we will create one. Depending on the subjective importance and urgency
as perceived by the ISC engineer, the issue and/or MR will be assigned to one of the milestones.

## Merge Request (also known as sending your patch the right way)

The first step in writing the patch or new feature should be to get the source code from our Git
repository. The procedure is very easy and is [explained here](https://gitlab.isc.org/isc-projects/dhcp/wikis/gitlab-howto).
While it is possible to provide a patch against the latest stable release, it makes the review
process much easier if it is for latest code from the Git master branch.

Since you won't get write access to the ISC DHCP repository, you should fork it and then commit
your changes to your own repo. How you organize the work depends entirely on you, but it seems
reasonable to create a branch rather than working on your master.  Once you feel that your patch
is ready, please commit your changes and push it to your copy of Kea repo. Then go to Kea project
and [submit a Merge Request](https://gitlab.isc.org/isc-projects/kea/merge_requests/new).

TODO: I don't think this is necessary. If you can't access this link or don't see New Merge Request
button on the [merge requests page](https://gitlab.isc.org/isc-projects/kea/merge_requests)
or the link gives you 404 error, please ask on dhcp-users and someone will help you out.

Once you submit it, someone from the DHCP development team will look at it and will get back to you.
The dev team is very small, so it may take a while...

## If you really can't do MR on gitlab...

Well, you are out of luck. There are other ways, but those are really awkward and the chances of
your patch being ignored are really high. Anyway, here they are:

- Create a ticket in the DHCP Gitlab (https://gitlab.isc.org/isc-projects/dhcp) and attach your
  patch to it. Sending a patch has a number of disadvantages. First, if you don't specify the base
  version against which it was created, one of ISC engineers will have to guess that or go through
  a series of trials and errors to find that out. If the code doesn't compile, the reviewer will not
  know if the patch is broken or maybe it was applied to incorrect base code. Another frequent
  problem is that it may be possible that the patch didn't include any new files you have added.

- Send a patch to the dhcp-workers list. This is even worse, but still better than not getting the
  patch at all. The problem with this approach is that we don't know which version the patch was
  created against and there is no way to track it. So the chances of it being forgotten are high.
  Once a DHCP developer get to it, the first thing he/she will have to do is try to apply your
  patch, create a branch commit your changes and then open MR for it.

## Going through a review

Once the MR is in the system, the action is on one of the ISC (and possibly other trusted) engineers.

Sooner or later, one of ISC engineers will do the review. Here's the tricky part. One of Kea
developers will review your patch, but it may not happen immediately. Unfortunately, developers
are usually working under a tight schedule, so any extra unplanned review work may take a while
sometimes. Having said that, we value external contributions very much and will do whatever we
can to review patches in a timely manner. Don't get discouraged if your patch is not accepted
after first review. To keep the code quality high, we use the same review processes for external
patches as we do for internal code. It may take some cycles of review/updated patch submissions
before the code is finally accepted. The nature of the review process is that it emphasizes areas
that need improvement. If you are not used to the review process, you may get the impression that
the feedback is negative. It is not: even the Kea developers seldom see reviews that say "All OK
please merge".

If we happen to have any comments that you as submitter are expected to address (and in the
overwhelming majority of cases, we have), you will be asked to update your MR. It is not
uncommon to see several rounds of such reviews, so this can get very complicated very quickly.

Once the process is almost complete, the developer will likely ask you how you would like to be
credited. The typical answers are by first and last name, by nickname, by company name or
anonymously. Typically we will add a note to the ChangeLog and also set you as the author of the
commit applying the patch and update the contributors section in the AUTHORS file. If the
contributed feature is big or critical for whatever reason, it may also be mentioned in release
notes.

Sadly, we sometimes see patches that are submitted and then the submitter never responds to our
comments or requests for an updated patch. Depending on the nature of the patch, we may either fix
the outstanding issues on our own and get another ISC engineer to review them or the ticket may end
up in our Outstanding milestone. When a new release is started, we go through the tickets in
Outstanding, select a small number of them and move them to whatever the current milestone is. Keep
that in mind if you plan to submit a patch and forget about it. We may accept it eventually, but
it's much, much faster process if you participate in it.

## Extra steps

If you are interested in knowing the results of more in-depth testing, you are welcome to visit the
ISC Jenkins page: https://jenkins.isc.org This is a live result page with all tests being run on
various systems. Besides basic unit-tests, we also have reports from valgrind (memory debugger),
cppcheck and clang-analyzer (static code analyzers), Lettuce system tests and more. Although it
is not possible for non ISC employees to run tests on that farm, it is possible that your
contributed patch will end up there sooner or later. We also have ISC Forge tests running and other
additional tests, but currently those test results are not publicly available.
