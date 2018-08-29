"""
The command line interface to cfn_nagger.

"""
from __future__ import absolute_import, division, print_function
import sys
import click
import inspect
import subprocess
import aws_bucket_creator
from aws_bucket_creator import BucketCreator

def lineno():
    """Returns the current line number in our program."""
    return str(' - BucketCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


@click.group()
@click.version_option(version='0.0.4')
def cli():
    pass


@cli.command()
@click.option('--days-to-standard-ia','-s',help='number of days before moving to standard_ia', required=False, is_flag=False, default=30)
@click.option('--days-to-glacier','-g',help='number of days before moving to glacier', required=False, is_flag=False,default=365)
@click.option('--bucket-policy-principals','-w',help='comma separated list of bucket policy principals', required=False, is_flag=False)
@click.option('--bucket-name','-b',help='bucket-name', required=True, is_flag=False)
@click.option('--aws-profile','-p',help='aws profile', required=True, is_flag=False)
@click.option('--required-tags','-r',help='comma delimited list of tag key names', required=False, is_flag=False)
@click.option('--required-values','-t',help='comma delimited list of tag key values', required=False, is_flag=False)
@click.option('--version', '-v', help='Print version and exit', required=False, is_flag=True)
@click.option('--debug',help='Turn on debugging', required=False, is_flag=True)
def create(
             days_to_standard_ia,
             days_to_glacier,
             bucket_policy_principals,
             bucket_name,
             aws_profile,
             required_tags,
             required_values,
             version,
             debug
             ):
    '''
    primary function for creating a bucket
    :return:
    '''

    if debug:
        debug = True
    else:
        debug = False

    if version:
        myversion()
    else:
        start_create(
            days_to_standard_ia,
            days_to_glacier,
            bucket_policy_principals,
            bucket_name,
            aws_profile,
            required_tags,
            required_values,
            debug
        )




@click.option('--version', '-v', help='Print version and exit', required=False, is_flag=True)
def version(version):
    """
    Get version
    :param version:
    :return:
    """
    myversion()


def myversion():
    '''
    Gets the current version
    :return: current version
    '''
    print('Version: '+str(aws_bucket_creator.__version__))

def start_create(
        days_to_standard_ia,
        days_to_glacier,
        bucket_policy_principals,
        bucket_name,
        aws_profile,
        required_tags,
        required_values,
        debug
    ):
    '''
    Starts the creation
    :return:
    '''
    if debug:
        print('command - start_create'+lineno())
        print('bucket: '+str(bucket_name))


    config_dict = {}
    config_dict['debug'] = debug
    config_dict['bucket_name'] = bucket_name
    config_dict['aws_profile'] = aws_profile
    config_dict['required_tags'] = required_tags
    config_dict['required_values'] = required_values
    config_dict['bucket_policy_principals'] = bucket_policy_principals
    config_dict['days_to_glacier']= days_to_glacier
    config_dict['days_to_standard_ia'] = days_to_standard_ia
    creator = BucketCreator(config_dict)
    if debug:
        print('print have BucketCreator')
    if creator.create():
        if debug:
            print('created')
    else:
        if debug:
            print('not created')


