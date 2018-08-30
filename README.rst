
AWS Bucket Creator
==================

Features
========

aws-bucket-creator creates a bucket, sets tags, logging, encryption, lifecycle, and policy


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
      -i, --ini TEXT  INI file with needed information  [required]
      -v, --version   Print version and exit
      --debug         Turn on debugging
      --help          Show this message and exit.



.. code:: console

   $bucket-creator create -i config/my.ini


Example Ini file

.. code:: console

    [environment]
    region = us-east-1
    profile = myprofile

    [tags]
    ResourceOwner = no_me
    Project = some project
    DeployedBy = me


    [parameters]
    bucket_name = test-bucket
    acl = bucket-owner-full-control
    public_write_access = True
    logging_enabled = True
    days_to_glacier = 365
    days_to_standard_ia = 30
    event_lambda_arn = arn:aws:lambda:us-east-1:123456789:function:my-lambda
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRoot",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::123456789:root"
                    ]
                },
                "Action": ["s3:*"],
                "Resource": [
                    "arn:aws:s3:::test-bucket/*",
                    "arn:aws:s3:::test-bucket"
                ]
            },
            {
                "Sid": "IPAllow",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::test-bucket/*",
                    "arn:aws:s3:::test-bucket"
                ],
                "Condition" : {
                    "IpAddress" : {
                        "aws:SourceIp": "192.128.1.1/32"
                    },
                    "NotIpAddress" : {
                        "aws:SourceIp": "192.168.1.1/32"
                    }
                }
            }
        ]
      }



