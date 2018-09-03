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


Demonstration
=============

<p><a target="_blank" rel="noopener noreferrer" href="https://github.com/rubelw//aws_bucket_creator/blob/master/images/demo.gif"><img src="https://github.com/rubelw//aws_bucket_creator/raw/master/images/demo.gif" alt="aws_bucket_creator tutorial" style="max-width:100%;"></a></p>



Example
=======
Getting help

.. code:: console

   $ bucket-creator create --help
   Usage: bucket-creator upsert [OPTIONS]

   primary function for creating a bucket :return:

    Options:
      -i, --ini TEXT  INI file with needed information  [required]
      -v, --version   Print version and exit
      --debug         Turn on debugging
      --help          Show this message and exit.



.. code:: console

   bucket-creator upsert -i config/my.ini

Options

    * acl can be: 'private', 'public-read', 'public-read-write', 'authenticated-read', 'aws-exec-read', 'bucket-owner-read','bucket-owner-full-control'
    * aes-256 encryption is turned-on by default, and can not be turned off for security reasons
    * public_read access can not be turned on for security reasons
    * default days before going to standard-ia is 30
    * default days before going to glacier is 365

Example Ini file

.. code:: console

    [environment]
    region = us-east-1
    profile = my_aws_profile

    [tags]
    ResourceOwner = not_me
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
    notification_prefix = input/
    notification_suffix = .jpg
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