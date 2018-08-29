from __future__ import absolute_import, division, print_function
import logging
import inspect
import botocore
import boto3
import sys
import json
import time
from botocore.exceptions import ClientError



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
        self.required_tags = None
        self.required_values = None
        self.tags = {}
        self.bucket_policy_principals = []
        self.bucket_policy = None
        self.days_to_glacier = 365
        self.days_to_standard_ia = 30

        if config_block:
            self._config = config_block
        else:
            logging.error('config block was garbage')
            raise SystemError

        if self._config['debug']:
            self.debug = self._config['debug']

        if self._config['days_to_glacier']:
            self.days_to_glacier = int(self._config['days_to_glacier'])

        if self._config['days_to_standard_ia']:
            self.days_to_standard_ia = int(self._config['days_to_standard_ia'])

        if self._config['bucket_policy_principals']:
            self.bucket_policy_principals = self._config['bucket_policy_principals'].split(',')

        if self._config['bucket_name']:
            self.bucket_name = self._config['bucket_name']

        if self._config['required_tags']:
            self.required_tags = self._config['required_tags'].strip('"').strip('\'').strip(' ').split(',')

            if self._config['required_tags'] and not self._config['required_values']:
                print('Need to have required_values set if required_tags is set')
                sys.exit(1)
            else:
                self.required_values = self._config['required_values'].split(',')

                # setup tags dict
                count_of_tag_names = int(len(self.required_tags))
                count_of_tag_values = int(len(self.required_values))

                if count_of_tag_values != count_of_tag_names:
                    print('Need to have the same number of key names and values')
                    sys.exit(1)
                else:

                    if self.debug:
                        print('tag name count: '+str(count_of_tag_names)+lineno())
                        print('tag value count: '+str(count_of_tag_values)+lineno())
                        print('required_tags: '+str(self.required_tags)+lineno())
                        print('required_values: '+str(self.required_values)+lineno())

                    for x in range(0, count_of_tag_names):
                        if self.debug:
                            print('count: '+str(x)+lineno())
                            print('value: '+str(self.required_values[x])+lineno())
                            print('name: '+str(self.required_tags[x])+lineno())
                        temp_name = self.required_tags[x]
                        temp_value = self.required_values[x]
                        self.tags[str(temp_name)]= str(temp_value)

                    if self.debug:
                        print('tags are: '+str(self.tags)+lineno())


        # Get boto session
        self.session = boto3.session.Session(profile_name=self._config['aws_profile'])
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
        self.create_encryption()
        self.create_logging()
        self.create_tags()

        if self.bucket_policy_principals:
            self.create_bucket_policy()
            self.add_bucket_policy()
        self.add_lifecycle_policy()



    def create_logging(self):


        try:
            response = self.client.get_bucket_logging(
                Bucket=self.bucket_name
            )
        except ClientError as e:
            print('no bucket logging')

            response = self.client.put_bucket_logging(
                Bucket=self.bucket_name,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': 'string',
                        'TargetGrants': [
                            {
                                'Grantee': {
                                    'DisplayName': 'string',
                                    'EmailAddress': 'string',
                                    'ID': 'string',
                                    'Type': 'CanonicalUser' | 'AmazonCustomerByEmail' | 'Group',
                                    'URI': 'string'
                                },
                                'Permission': 'FULL_CONTROL' | 'READ' | 'WRITE'
                            },
                        ],
                        'TargetPrefix': 'string'
                    }
                },

            )

            print(response)

    def create_encryption(self):

        try:
            response = self.client.get_bucket_encryption(
                Bucket=self.bucket_name
            )
            print(response)
        except ClientError as e:
            print('no bucket encryption')
            print('')
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

        except ClientError as e:
            print('Error adding bucket lifecycle policy: ' + str(e))


    def add_bucket_policy(self):
        # Add bucket policy

        try:
            response = self.client.put_bucket_policy(Bucket=self.bucket_name, Policy=json.dumps(self.bucket_policy))
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

        if self.check_bucket():
            # Bucket already exists - this is good
            tags_to_check= self.check_tags()

            if self.debug:
                print('tags to check: '+str(tags_to_check))

            if tags_to_check:

                try:

                    data = []
                    for tag in tags_to_check:
                        temp_dict = {}
                        temp_dict['Key']=str(tag)
                        temp_dict['Value']= str(self.tags[tag])

                        data.append(temp_dict)
                    if self.debug:
                        print('new tag info: '+str(data)+lineno())

                    response = self.client.put_bucket_tagging(
                        Bucket=str(self.bucket_name),
                        Tagging={
                            'TagSet': data
                        }
                    )

                    if self.debug:
                        print('response: '+str(response))

                except ClientError as e:
                    print('Error creating tags: '+str(e))

                    if 'NoSuchTagSet' in str(e):
                        print('We need to wait for 90 seconds while the bucket gets created in AWS')
                        time.sleep(90)

                        try:

                            data = []
                            for tag in tags_to_check:
                                temp_dict = {}
                                temp_dict['Key'] = str(tag)
                                temp_dict['Value'] = str(self.tags[tag])

                                data.append(temp_dict)
                            if self.debug:
                                print('new tag info: ' + str(data) + lineno())

                            response = self.client.put_bucket_tagging(
                                Bucket=str(self.bucket_name),
                                Tagging={
                                    'TagSet': data
                                }
                            )

                            if self.debug:
                                print('response: ' + str(response))

                        except ClientError as err:
                            print('Error creating tags: ' + str(err))

            else:
                print('Create the bucket before trying to add tags')
                sys.exit(1)


    def create_bucket(self):
        if self.debug:
            print('create bucket'+lineno())

        if self.check_bucket():
            # Bucket already exists
            return
        else:
            # Create bucket

            try:
                print('Creating bucket')
                response = self.client.create_bucket(Bucket=str(self.bucket_name))


                print('response: '+str(response)+lineno())

            except ClientError as e:
                print('Error: '+str(e))
                sys.exit(1)

    def check_tags(self):

        if self.required_tags and len(self.required_tags)>0:

            try:

                response = self.client.get_bucket_tagging(
                    Bucket=str(self.bucket_name)
                )

                tags = {}
                for tag in self.required_tags:
                    tags[tag] = False


                if 'TagSet' in response:
                    for tagset in response['TagSet']:

                        if tagset['Key'] in tags:
                            if self.debug:
                                print('found key'+lineno())

                            tags[tagset['Key']] = True

                return tags
            except botocore.exceptions.ClientError as e:
                print('Error checking tags: '+str(e)+lineno())


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
