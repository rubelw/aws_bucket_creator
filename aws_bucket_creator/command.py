"""
The command line interface to cfn_nagger.

"""
from __future__ import absolute_import, division, print_function
import sys
import click
import inspect
import subprocess
import boto3
import aws_bucket_creator
from configparser import RawConfigParser
from aws_bucket_creator import BucketCreator
import logging
import json
import traceback

def lineno():
    """Returns the current line number in our program."""
    return str(' - BucketCreator - line number: '+str(inspect.currentframe().f_back.f_lineno))


@click.group()
@click.version_option(version='0.0.11')
def cli():
    pass


@cli.command()
@click.option('--ini', '-i', help='INI file with needed information', required=True)
@click.option('--version', '-v', help='Print version and exit', required=False, is_flag=True)
@click.option('--debug',help='Turn on debugging', required=False, is_flag=True)
def create(
             ini,
             version,
             debug
    ):
    '''
    primary function for creating a bucket
    :return:
    '''

    ini_data = read_config_info(ini)
    if 'environment' not in ini_data:
        print('[environment] section is required in the INI file')
        sys.exit(1)


    if debug:
        ini_data['parameters']['debug'] = True
    else:
        ini_data['parameters']['debug'] = False


    if 'region' not in ini_data['environment']:
        ini_data['environment']['region'] = find_myself()

    if version:
        myversion()
    else:
        start_create(
            ini_data,
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
        ini,
        debug
    ):
    '''
    Starts the creation
    :return:
    '''
    if debug:
        print('command - start_create'+lineno())
        print('ini data: '+str(ini)+lineno())


    config_dict = {}


    if 'debug' in ini['parameters']:

        if ini['parameters']['debug']:
            config_dict['debug'] = ini['parameters']['debug']
        else:
            config_dict['debug'] = False
    else:
        config_dict['debug'] = False

    if ini['parameters']['bucket_name']:
        config_dict['bucket_name'] = ini['parameters']['bucket_name']
    if ini['environment']['profile']:
        config_dict['aws_profile'] = ini['environment']['profile']
    if ini['environment']['region']:
        config_dict['region'] = ini['environment']['region']
    tags = []
    for tag in ini['tags']:
        temp_dict = {}
        temp_dict['Key'] = tag
        temp_dict['Value']= ini['tags'][tag]
        tags.append(temp_dict)

    # Add bucket name as tag
    temp_dict={}
    temp_dict['Key'] = 'Name'
    temp_dict['Value']= ini['parameters']['bucket_name']
    tags.append(temp_dict)


    if tags:
        config_dict['tags']= tags

    if 'logging_enable' in ini['parameters']:
        config_dict['logging_enabled'] = ini['parameters']['logging_enabled']
    else:
        config_dict['logging_enabled']= False

    if 'public_write_access' in ini['parameters']:
        config_dict['public_write_access'] = ini['parameters']['public_write_access']

    if 'acl' in ini['parameters']:
        config_dict['acl'] = ini['parameters']['acl']
    else:
        config_dict['acl'] = 'bucket-owner-full-control'

    if 'days_to_glacier' in ini['parameters']:
        config_dict['days_to_glacier'] = ini['parameters']['days_to_glacier']
    else:
        config_dict['days_to_glacier'] = 365

    if 'days_to_standarde_ia' in ini['parameters']:
        config_dict['days_to_standard_ia'] = ini['parameters']['days_to_standard_ia']
    else:
        config_dict['days_to_standard_ia'] = 30


    if 'principals' in ini['parameters']:
        config_dict['bucket_policy_principals'] = ini['parameters']['principals']

    if 'bucket_policy' in ini['parameters']:
        config_dict['bucket_policy'] = ini['parameters']['bucket_policy']


    if 'bucket_policy_path' in ini['parameters']:
        config_dict['days_to_standard_ia'] = ini['parameters']['bucket_policy_path']
    else:
        config_dict['bucket_policy_path'] = None

    if 'event_lambda_arn' in ini['parameters']:
        config_dict['event_lambda_arn'] = ini['parameters']['event_lambda_arn']


    creator = BucketCreator(config_dict)
    if debug:
        print('print have BucketCreator')
    if creator.create():
        if debug:
            print('created')
    else:
        if debug:
            print('not created')

def find_myself():
    """
    Find myself
    Args:
        None
    Returns:
       An Amazon region
    """
    s = boto3.session.Session()
    return s.region_name

def read_config_info(ini_file):
    """
    Read the INI file
    Args:
        ini_file - path to the file
    Returns:
        A dictionary of stuff from the INI file
    Exits:
        1 - if problems are encountered
    """
    try:
        config = RawConfigParser()
        config.optionxform = lambda option: option
        config.read(ini_file)
        the_stuff = {}
        for section in config.sections():
            the_stuff[str(section)] = {}
            for option in config.options(section):
                the_stuff[str(section)][str(option)] = str(config.get(section, option.replace('\n','')))

        return the_stuff
    except Exception as wtf:
        logging.error('Exception caught in read_config_info(): {}'.format(wtf))
        traceback.print_exc(file=sys.stdout)
        return sys.exit(1)



