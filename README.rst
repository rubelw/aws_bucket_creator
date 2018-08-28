
AWS Bucket Creator
==================

Features
========

aws-bucket-creator creates a bucket and sets tags, lifecycle, and policy


Installation
============

aws-bucket-creator is on PyPI so all you need is:

.. code:: console

   $ pip install aws-bucket-creator


Example
=======

Getting help

.. code:: console

   $ bucket-creator create --help
   Usage: bucket-creator create [OPTIONS]

   primary function for creating a bucket :return:

   Options:
     -d, --days-to_glacier TEXT      number of days before moving to glacier
     -w, --bucket-policy-principals TEXT
                                     comma separated list of bucket policy
                                     principals
     -b, --bucket-name TEXT          bucket-name  [required]
     -p, --aws-profile TEXT          aws profile  [required]
     -r, --required-tags TEXT        comma delimited list of tag key names
     -t, --required-values TEXT      comma delimited list of tag key values
     -v, --version                   Print version and exit
     --debug                         Turn on debugging
     --help                          Show this message and exit.



.. code:: console

   $bucket-creator create -b test-bucket -p my-profile -r Name,Project,DeployedBy,ResourceOwner -t test,io,test,test -w arn:aws:iam::12343434:root



