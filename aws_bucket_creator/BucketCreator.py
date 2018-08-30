from __future__ import absolute_import, division, print_function
import logging
import inspect
import botocore
import boto3
import sys
import json
import time
import os
from botocore.exceptions import ClientError
from boto.s3.acl import ACL, Grant



def lineno():
    """Returns the current line number in our program."""
    return str(' - BucketCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


class BucketCreator:

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


        if config_block:
            self._config = config_block
        else:
            logging.error('config block was garbage')
            raise SystemError

        if self._config['debug']:
            self.debug = self._config['debug']


        if self._config['tags']:
            self.tags = self._config['tags']

        if self._config['region']:
            self.region = self._config['region']

        if self._config['public_write_access']:
            self.public_write_access = self._config['public_write_access']

        if self._config['acl']:
            self.acl = self._config['acl']

        if self._config['days_to_glacier']:
            self.days_to_glacier = int(self._config['days_to_glacier'])

        if self._config['days_to_standard_ia']:
            self.days_to_standard_ia = int(self._config['days_to_standard_ia'])

        if self._config['bucket_policy_principals']:
            self.bucket_policy_principals = self._config['bucket_policy_principals'].split(',')

        if self._config['bucket_name']:
            self.bucket_name = self._config['bucket_name']

        if self._config['bucket_policy_path']:
            self.bucket_policy_path = self._config['bucket_policy_path']
            self.bucket_policy = self.load_bucket_policy()

            if self.debug:
                print('bucket policy is: '+str(self.bucket_policy)+lineno())

        # Get boto session
        if self.region:
            self.session = boto3.session.Session(profile_name=self._config['aws_profile'], region_name=self.region)
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

        if self.bucket_policy_principals and not self.bucket_policy_path:

            if self.debug:
                print('There are principals in the policy but no bucket policy path'+lineno())
            self.create_bucket_policy()
            self.add_bucket_policy()
        elif self.bucket_policy_path:
            if self.debug:
                print('There is a bucket policy path...creating bucket policy'+lineno())
            self.add_bucket_policy()
        self.add_lifecycle_policy()


    def get_bucket_owner_id(self):

        try:
            response = self.client.get_bucket_acl(
                Bucket=self.bucket_name
            )

            if self.debug:
                print('response: '+str(response))

            if 'Owner' in response:
                self.bucket_owner_id = response['Owner']['ID']
                self.bucket_owner_display_name = response['Owner']['DisplayName']

        except ClientError as e:
            print('Could not get bucket owner id: '+str(e))



    def create_acl(self):

        try:
            response = self.client.get_bucket_logging(
                Bucket=self.bucket_name
            )

            if self.debug:
                print('acl response: '+str(response))

            if self.public_write_access:
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

        except ClientError as e:
            print('Error creating bucket acl: '+str(e))



    def load_bucket_policy(self):
        if self.debug:
            print('load bucket policy')
            print('current directory is: ' + str(os.getcwd()))

        if str(self.bucket_policy_path).startswith('./'):
            self.bucket_policy_path = str(os.getcwd())+'/'+str(self.bucket_policy_path.replace('./',''))

            if self.debug:
                print('new bucket path is: '+str(self.bucket_policy_path))
        if not str(self.bucket_policy_path).startswith('/'):
            self.bucket_policy_path = os.getcwd()+'/'+str(self.bucket_policy_path)

            if self.debug:
                print('new bucket path is: '+str(self.bucket_policy_path))

        try:
            with open(self.bucket_policy_path, 'r') as tempfile:  # OSError if file exists or is invalid
                pass

            with open(self.bucket_policy_path) as f:
                bucket_policy = json.dumps((json.load(f)))

                if self.debug:
                    print('bucket policy is: ' + str(self.bucket_policy)+lineno())

                return bucket_policy

        except OSError:
            print('could not open the bucket policy file')



    def create_logging(self):


        try:
            response = self.client.get_bucket_logging(
                Bucket=self.bucket_name
            )

            if self.debug:
                print('bucket logging response: '+str(response))


            if not 'LoggingEnabled' in response:

                if self.debug:
                    print('no bucket logging')

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

        except ClientError as e:
            print('Error creating bucket logging: '+str(e))


    def create_encryption(self):

        try:
            response = self.client.get_bucket_encryption(
                Bucket=self.bucket_name
            )
            if self.debug:
                print(response)
        except ClientError as e:
            if self.debug:
                print('no bucket encryption')

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
        except ClientError as e:
            print('Error adding bucket lifecycle policy: ' + str(e))


    def add_bucket_policy(self):
        # Add bucket policy

        try:

            if self.debug:
                print('policy is: '+str(str(self.bucket_policy).replace('"','\''))+lineno())

            if self.bucket_policy_path:
                response = self.client.put_bucket_policy(Bucket=self.bucket_name, Policy=json.loads(json.dumps(self.bucket_policy)))

                if self.debug:
                    print(response)

            else:
                response = self.client.put_bucket_policy(Bucket=self.bucket_name, Policy=json.dumps(self.bucket_policy))
                if self.debug:
                    print(response)

        except ClientError as e:
            print('Error adding bucket policy: ' + str(e))


    def create_bucket_policy(self):

        data = {}
        data['Version'] = "2012-10-17"
        data['Statement'] = []
        data['Statement'].append({})
        data['Statement'][0]["Sid"]="AllowRoot"
        data['Statement'][0]["Effect"]="Allow"
        data['Statement'][0]["Principal"]= {}
        data['Statement'][0]["Principal"]["AWS"]= []
        data['Statement'][0]["Action"]= []
        data['Statement'][0]["Action"].append("s3:*")
        data['Statement'][0]["Resource"]=[]
        data['Statement'][0]["Resource"].append("arn:aws:s3:::"+str(self.bucket_name)+"/*")
        data['Statement'][0]["Resource"].append("arn:aws:s3:::"+str(self.bucket_name))


        for principal in self.bucket_policy_principals:
            data["Statement"][0]["Principal"]["AWS"].append(principal)

        self.bucket_policy=data

    def create_tags(self):
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

            except ClientError as e:
                print('Error creating tags: '+str(e))

        else:
            print('Create the bucket before trying to add tags')
            sys.exit(1)


    def create_bucket(self):
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

            except ClientError as e:
                print('Error: '+str(e))
                sys.exit(1)


    def check_bucket(self):
        try:
            self.resource.meta.client.head_bucket(Bucket=self.bucket_name)
            if self.debug:
                print("Bucket Already Exists!")

            return True
        except botocore.exceptions.ClientError as e:
            # If a client error is thrown, then check that it was a 404 error.
            # If it was a 404 error, then the bucket does not exist.
            error_code = int(e.response['Error']['Code'])
            if error_code == 403:
                if self.debug:
                    print("Bucket Already Exists - Private Bucket. Forbidden Access!")
                return True
            elif error_code == 404:
                if self.debug:
                    print("Bucket Does Not Exist!")
                return False




