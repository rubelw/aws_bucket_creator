from __future__ import absolute_import, division, print_function
import logging
import inspect
import os
import sys
import json
import time
import botocore
import boto3
from botocore.exceptions import ClientError
from boto.s3.acl import ACL, Grant



def lineno():
    """Returns the current line number in our program."""
    return str(' - BucketCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


class BucketCreator:
    """
    Creates an S3 Bucket
    """

    def __init__(self, config_block):
        """
        Initialize BucketCreator
        :param config_block:
        """

        self.debug = False
        self.bucket_name = None
        self.aws_profile = None
        self.session = None
        self.client = None
        self.resource = None
        self.tags = None
        self.bucket_policy_principals = []
        self.bucket_policy = None
        self.bucket_policy_path = None
        self.days_to_glacier = 365
        self.days_to_standard_ia = 30
        self.acl = None
        self.bucket_owner_id = None
        self.bucket_owner_display_name = None
        self.public_write_access = False
        self.region = None
        self.event_lambda_arn = None
        self.logging_enabled = False
        self.notification_prefix = None
        self.notification_suffix = None


        if config_block:
            self._config = config_block
        else:
            logging.error('config block was garbage')
            raise SystemError

        if 'debug' in self._config:
            self.debug = self._config['debug']


        if 'tags' in self._config:
            self.tags = self._config['tags']

        if 'notification_prefix' in self._config:
            self.notification_prefix = self._config['notification_prefix']

        if 'notification_suffix' in self._config:
            self.notification_suffix = self._config['notification_suffix']

        if 'logging_enabled' in self._config:
            self.logging_enabled = self._config['logging_enabled']


        if 'region' in self._config:
            self.region = self._config['region']

        if 'public_write_access' in self._config:
            self.public_write_access = self._config['public_write_access']

        if 'acl' in self._config:
            self.acl = self._config['acl']

        if 'days_to_glacier' in self._config:
            self.days_to_glacier = int(self._config['days_to_glacier'])

        if 'days_to_standard_ia' in self._config:
            self.days_to_standard_ia = int(self._config['days_to_standard_ia'])

        if 'bucket_policy_principals' in self._config:
            self.bucket_policy_principals = self._config['bucket_policy_principals'].split(',')

        if 'bucket_name' in self._config:
            self.bucket_name = self._config['bucket_name']

        if 'bucket_policy_path' in self._config:
            self.bucket_policy_path = self._config['bucket_policy_path']

        if 'event_lambda_arn' in self._config:
            self.event_lambda_arn = self._config['event_lambda_arn']

        if 'bucket_policy' in self._config:
            self.bucket_policy = self._config['bucket_policy']


            if self.debug:
                print('bucket policy is: '+str(self.bucket_policy)+lineno())

        # Get boto session
        if self.region:
            self.session = boto3.session.Session(
                profile_name=self._config['aws_profile'],
                region_name=self.region
            )

        elif self.aws_profile:
            self.session = boto3.session.Session(profile_name=self._config['aws_profile'])
        else:
            self.session = boto3.session.Session()

        self.client = self.session.client('s3')
        self.resource = self.session.resource('s3')

        if self.debug:
            print('s3 bucket: '+str(self.bucket_name))


    def create(self):
        """
        Create a bucket
        :return: rendered results
        """

        if self.debug:
            print('BucketCreator - create'+lineno())

        self.create_bucket()
        print('Bucket created')
        self.get_bucket_owner_id()
        print('Found bucket owner id')
        self.create_acl()
        print('Bucket acl created')
        self.create_encryption()
        print('Encryption set')
        self.create_logging()
        print('Bucket logging set')
        self.create_tags()
        print('Bucket tags set')

        if len(self.bucket_policy_principals) > 0 and not self.bucket_policy_path:

            if self.debug:
                print('There are principals in the policy but no bucket policy path'+lineno())

            if not self.bucket_policy:
                self.create_bucket_policy()
            else:
                if self.debug:
                    print('## There is a bucket policy being passed-in')

            self.add_bucket_policy()
        elif len(self.bucket_policy_principals) < 1 and self.bucket_policy and not self.bucket_policy_path:
            if self.debug:
                print('## There is a bucket policy being passed-in')

            self.add_bucket_policy()

        elif self.bucket_policy_path:
            if self.debug:
                print('There is a bucket policy path...creating bucket policy'+lineno())
            self.bucket_policy = self.load_bucket_policy()
            self.add_bucket_policy()
        self.add_lifecycle_policy()
        print('Lifecycle policy added')

        self.create_bucket_notifications()
        print('Bucket notifications set')


    def create_bucket_notifications(self):
        """
        Create bucket notification
        :return:
        """
        if self.event_lambda_arn:


            data = {
                        'LambdaFunctionConfigurations': [
                            {
                                'Id': 'MyEvent',
                                'LambdaFunctionArn': self.event_lambda_arn,
                                'Events': [
                                    's3:ObjectCreated:Put',
                                ]
                            }
                        ]
                    }

            if self.notification_suffix:
                data['LambdaFunctionConfigurations'][0]['Filter']={}
                data['LambdaFunctionConfigurations'][0]['Filter']['Key'] = {}
                data['LambdaFunctionConfigurations'][0]['Filter']['Key']['FilterRules']=[]
                temp_dict = {}
                temp_dict['Name']= 'suffix'
                temp_dict['Value'] = str(self.notification_suffix)
                data['LambdaFunctionConfigurations'][0]['Filter']['Key']['FilterRules'].append(temp_dict)


            if self.notification_prefix:

                if self.debug:
                    print('## There is a prefix')

                # If an existing filter exists
                if 'Filter' in  data['LambdaFunctionConfigurations'][0]:
                    temp_dict = {}
                    temp_dict['Name'] = 'prefix'
                    temp_dict['Value'] = str(self.notification_prefix)
                    data['LambdaFunctionConfigurations'][0]['Filter']['Key']['FilterRules'].append(temp_dict)
                else:
                    if self.debug:
                        print('There is not an existing filter')

                    data['LambdaFunctionConfigurations'][0]['Filter'] = {}
                    data['LambdaFunctionConfigurations'][0]['Filter']['Key'] = {}
                    data['LambdaFunctionConfigurations'][0]['Filter']['Key']['FilterRules'] = []
                    temp_dict = {}
                    temp_dict['Name'] = 'prefix'
                    temp_dict['Value'] = str(self.notification_prefix)
                    data['LambdaFunctionConfigurations'][0]['Filter']['Key']['FilterRules'].append(temp_dict)


            try:

                if self.debug:
                    print('notification data is: '+str(json.dumps(data)))

                response = self.client.put_bucket_notification_configuration(
                    Bucket=self.bucket_name,
                    NotificationConfiguration=data
                )

                if self.debug:
                    print('response: ' + str(response))

            except ClientError as err:
                print('Could not get create bucket event: ' + str(err))



    def get_bucket_owner_id(self):
        """
        Get bucket owner id
        :return:
        """
        try:
            response = self.client.get_bucket_acl(
                Bucket=self.bucket_name
            )

            if self.debug:
                print('response: '+str(response))

            if 'Owner' in response:
                self.bucket_owner_id = response['Owner']['ID']
                self.bucket_owner_display_name = response['Owner']['DisplayName']

        except ClientError as err:
            print('Could not get bucket owner id: '+str(err))



    def create_acl(self):
        """
        Create bucket ACL
        :return:
        """
        try:
            response = self.client.get_bucket_logging(
                Bucket=self.bucket_name
            )

            if self.debug:
                print('acl response: '+str(response))

            if self.public_write_access:

                if self.debug:
                    print('setting acl to public write')


                response = self.client.put_bucket_acl(
                    Bucket=self.bucket_name,
                    AccessControlPolicy={
                        'Grants': [
                            {
                                'Grantee': {
                                    'Type': 'Group',
                                    'URI': 'http://acs.amazonaws.com/groups/global/AllUsers',
                                },
                                'Permission': 'WRITE'
                            },
                            {
                                'Grantee': {
                                    'Type': 'Group',
                                    'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                                },
                                'Permission':  'WRITE'
                            },
                            {
                                'Grantee': {
                                    'Type': 'Group',
                                    'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                                },
                                'Permission': 'READ_ACP'
                            },
                        ],
                        'Owner': {
                            'DisplayName': 'Owner',
                            'ID': self.bucket_owner_id
                        }
                    }
                )

                if self.debug:
                    print(response)

            else:

                if self.debug:
                    print('## Setting access control to bucket owner only')

                response = self.client.put_bucket_acl(
                    Bucket=self.bucket_name,
                    AccessControlPolicy={
                        'Grants': [
                            {
                                'Grantee': {
                                    'Type': 'Group',
                                    'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                                },
                                'Permission':  'WRITE'
                            },
                            {
                                'Grantee': {
                                    'Type': 'Group',
                                    'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                                },
                                'Permission': 'READ_ACP'
                            },
                        ],
                        'Owner': {
                            'DisplayName': 'Owner',
                            'ID': self.bucket_owner_id
                        }
                    }
                )
            if self.debug:
                print(response)

        except ClientError as err:
            print('Error creating bucket acl: '+str(err))



    def load_bucket_policy(self):
        """
        Load a bucket policy from a file
        :return:
        """
        if self.debug:
            print('load bucket policy')
            print('current directory is: ' + str(os.getcwd()))

        if str(self.bucket_policy_path).startswith('./'):
            self.bucket_policy_path = str(os.getcwd())+'/'+str(self.bucket_policy_path.replace('./', ''))

            if self.debug:
                print('new bucket path is: '+str(self.bucket_policy_path))
        if not str(self.bucket_policy_path).startswith('/'):
            self.bucket_policy_path = os.getcwd()+'/'+str(self.bucket_policy_path)

            if self.debug:
                print('new bucket path is: '+str(self.bucket_policy_path))

        try:
            with open(self.bucket_policy_path, 'r') as tempfile:  # OSError if file exists or is invalid
                pass

            with open(self.bucket_policy_path) as policy_file:
                bucket_policy = json.dumps((json.load(policy_file)))

                if self.debug:
                    print('bucket policy is: ' + str(self.bucket_policy)+lineno())

                return bucket_policy

        except OSError:
            print('could not open the bucket policy file')



    def create_logging(self):
        """
        Turn on logging for a bucket, or turn it off
        :return:
        """

        if self.debug:
            print('######################')
            print('Create logging')
            print('flag: '+str(self.logging_enabled))
            print('######################')

        try:
            response = self.client.get_bucket_logging(
                Bucket=self.bucket_name
            )

            if self.debug:
                print('bucket logging response: '+str(response))


            if not 'LoggingEnabled' in response:

                if self.debug:
                    print('no bucket logging')

                if self.logging_enabled:

                    response = self.client.put_bucket_logging(
                        Bucket=self.bucket_name,
                        BucketLoggingStatus={
                            'LoggingEnabled': {
                                'TargetBucket': self.bucket_name,
                                'TargetPrefix': 'user/',
                                'TargetGrants': [
                                    {
                                        'Grantee': {
                                            'Type': 'Group',
                                            'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                                        },
                                        'Permission': 'WRITE'
                                    },
                                    {
                                        'Grantee': {
                                            'Type': 'Group',
                                            'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                                        },
                                        'Permission': 'READ'
                                    },
                                ]
                            }
                        }

                    )

                    if self.debug:
                        print(response)

            # If logging is enabled
            else:
                if not self.logging_enabled:

                    response = self.client.put_bucket_logging(
                        Bucket=self.bucket_name,
                        BucketLoggingStatus={
                        }

                    )

                    if self.debug:
                        print(response)

        except ClientError as err:
            print('Error creating bucket logging: '+str(err))

    def create_encryption(self):
        """
        Set encryption on a bucket
        :return:
        """
        try:
            response = self.client.get_bucket_encryption(
                Bucket=self.bucket_name
            )
            if self.debug:
                print(response)
        except ClientError as err:
            if self.debug:
                print('no bucket encryption:'+str(err))

            response = self.client.put_bucket_encryption(
                Bucket=self.bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )

            if self.debug:
                print(response)


    def add_lifecycle_policy(self):
        """
        Add a lifecycle policy to a bucket
        :return:
        """
        try:
            response = self.client.put_bucket_lifecycle_configuration(
                Bucket=self.bucket_name,
                LifecycleConfiguration={
                    'Rules': [
                        {
                            'ID': 'MoveToStandardIa',
                            'Filter': {
                                'Prefix': ''
                            },
                            'Status': 'Enabled',
                            'Transitions': [
                                {
                                    'Days': self.days_to_standard_ia,
                                    'StorageClass': 'STANDARD_IA'
                                }
                            ]
                        },
                        {
                            'ID': 'MoveToGlacier',
                            'Filter':{
                                'Prefix':''
                            },
                            'Status': 'Enabled',
                            'Transitions': [
                                {
                                    'Days': self.days_to_glacier,
                                    'StorageClass': 'GLACIER'
                                }
                            ]

                        }
                    ]
                }
            )

            if self.debug:
                print(response)
        except ClientError as err:
            print('Error adding bucket lifecycle policy: ' + str(err))


    def add_bucket_policy(self):
        """
        Add a bucket policy
        :return:
        """

        try:

            if self.debug:
                print('##############################')
                print('policy is: '+str(str(self.bucket_policy).replace('"', '\''))+lineno())
                print('##############################')


            if self.bucket_policy_path:
                response = self.client.put_bucket_policy(
                    Bucket=self.bucket_name,
                    Policy=json.loads(json.dumps(self.bucket_policy))
                )

                if self.debug:
                    print(response)

            elif self.bucket_policy and (not self.bucket_policy_path and len(self.bucket_policy_principals) < 1):

                temp_policy_string = self.bucket_policy.replace("\n", '').replace('\'', '"')

                if self.debug:
                    print('temp_policy_string: '+str(temp_policy_string))

                dict_policy = json.loads(temp_policy_string)

                if self.debug:
                    #print('policy as json: '+str(temp_policy))
                    print('policy as dict: '+str(json.loads(temp_policy_string)))
                    print('dict type: '+str(type(dict_policy)))

                response = self.client.put_bucket_policy(
                    Bucket=self.bucket_name,
                    ConfirmRemoveSelfBucketAccess=False,
                    Policy=json.dumps(dict_policy).strip()
                )

                if self.debug:
                    print(response)

            else:
                response = self.client.put_bucket_policy(Bucket=self.bucket_name, Policy=json.dumps(self.bucket_policy))
                if self.debug:
                    print(response)

        except ClientError as err:
            print('Error adding bucket policy: ' + str(err))


    def create_bucket_policy(self):
        """
        Create S3 Bucket Policy
        :return:
        """
        data = {}
        data['Version'] = "2012-10-17"
        data['Statement'] = []
        data['Statement'].append({})
        data['Statement'][0]["Sid"] = "AllowRoot"
        data['Statement'][0]["Effect"] = "Allow"
        data['Statement'][0]["Principal"] = {}
        data['Statement'][0]["Principal"]["AWS"] = []
        data['Statement'][0]["Action"] = []
        data['Statement'][0]["Action"].append("s3:*")
        data['Statement'][0]["Resource"] = []
        data['Statement'][0]["Resource"].append("arn:aws:s3:::"+str(self.bucket_name)+"/*")
        data['Statement'][0]["Resource"].append("arn:aws:s3:::"+str(self.bucket_name))


        for principal in self.bucket_policy_principals:
            data["Statement"][0]["Principal"]["AWS"].append(principal)

        self.bucket_policy = data

    def create_tags(self):
        """
        Create tags on S3 bucket
        :return:
        """
        if self.debug:
            print('create tags'+lineno())

        while not self.check_bucket():
            print('Waiting for bucket to be created')
            print('Sleeping for 5 minutes')
            time.sleep(300)


        if self.debug:
            print('tags to check: '+str(self.tags))

        if self.tags:

            try:

                if self.debug:
                    print('new tag info: '+str(self.tags)+lineno())

                response = self.client.put_bucket_tagging(
                    Bucket=str(self.bucket_name),
                    Tagging={
                        'TagSet': self.tags
                    }
                )

                if self.debug:
                    print('response: '+str(response))

            except ClientError as err:
                print('Error creating tags: '+str(err))

        else:
            print('Create the bucket before trying to add tags')
            sys.exit(1)


    def create_bucket(self):
        """
        Create an S3 Bucket
        :return:
        """
        if self.debug:
            print('create bucket'+lineno())
            print('bucket name: '+str(self.bucket_name))

        if self.check_bucket():
            # Bucket already exists
            return
        else:
            # Create bucket

            try:
                if self.debug:
                    print('Creating bucket')
                response = self.client.create_bucket(Bucket=str(self.bucket_name))

                if self.debug:
                    print('response: '+str(response)+lineno())

            except ClientError as err:
                print('Error: '+str(err))
                sys.exit(1)


    def check_bucket(self):
        """
        Check if a bucket exists
        :return:
        """
        try:
            self.resource.meta.client.head_bucket(Bucket=self.bucket_name)
            if self.debug:
                print("Bucket Already Exists!")

            return True
        except botocore.exceptions.ClientError as err:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = int(err.response['Error']['Code'])
            if error_code == 403:
                if self.debug:
                    print("Bucket Already Exists - Private Bucket. Forbidden Access!")
                return True
            elif error_code == 404:
                if self.debug:
                    print("Bucket Does Not Exist!")
                return False
