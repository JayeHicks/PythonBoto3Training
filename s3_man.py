""" Provide a few basic operations on S3 buckets and S3 objects

Jaye Hicks Consulting, 2018
 **********************************************************************
 * Obligatory legal disclaimer:                                       *
 *  You are free to use this source code (this file and all other     *
 *  files referenced in this file) "AS IS" WITHOUT WARRANTY OF ANY    *
 *  KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, *
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A       *
 *  PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND         *
 *  PERFORMANCE OF THIS SOURCE CODE IS WITH YOU.  SHOULD THE SOURCE   *
 *  CODE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY        *
 *  SERVICING, REPAIR OR CORRECTION. See the GNU GENERAL PUBLIC       *
 *  LICENSE Version 3, 29 June 2007 for more details.                 *
 **********************************************************************
 
First argument specifies what action to take on account's S3 buckets.
AWS account that script works against is determined by the boto3 
session this script creates to enable access to AWS services. s3_man.py
can be supplied an IAM access key id and secret access key in order to 
select a specific AWS account or these credentials will default to the 
IAM credentials in the default profile residing in the 
".aws/credentials" file (created during AWS CLI installation on the 
machine on which you run s3_man.py).  If security credentials are 
supplied that are improperly formatted or otherwise invalid the 
credentials of the default profile will be used.  Some actions accept a 
region specification.  For these, if no region, or an invalid region, is 
specified the action will be applied across all regions.  s3_man.py will 
only work for AWS standard partitions; it will not work for 'aws-cn' or 
'aws-gov'. 
 
If a custom boto3 session is established by the script, an endpoint 
parameter can be used to specify which AWS regional endpoint to use 
when making API calls to AWS services.  The default is 'us-east-1'  

    
Args:
  command (str):        Required. 'create_s3', 'delete_s3', 'list_s3', 
                        'list_s3_objs', or 'delete_s3_obj'
  bucket  (str):        Optional. S3 bucket to apply the command to 
  key     (str):        Optional. Key of S3 object to apply command to
  file    (str):        Optional. File to upload for new S3 object
  value   (str):        Optional. String to convert to bytes value that 
                          will be value of newly created S3 object
  region  (str):        Optional. Region to apply command in
  id      (str):        Optional. AWS access key id for authorization
  secret  (str):        Optional. AWS secret access key for auth
  endpoint(str):        Optional. Regional endpoint for AWS API calls
  
  NOTE: file argument and value argument are mutually exclusive
  
Returns:
  (str): S3 bucket list or list of s3 bucket objects or success / fail
         message indicating results of command execution

Usage:  
  NOTE: First argument (i.e., action) is required; all others optional.
  python s3_man.py create_s3 -b my-bucket
  python s3_man.py create_s3 -b my-bucket -r us-east-1
  python s3_man.py delete_s3 -b my-bucket
  python s3_man.py list_s3
  python s3_man.py list_s3 -r us-east-1
  python s3_man.py list_s3_objs -b my-bucket
  python s3_man.py delete_s3_obj -b my-bucket -k my-object
  python s3_man.py add_s3_obj -b my-bucket -k my-file.txt 
  -f 'C:\my-file.txt'
  python s3_man.py add_s3_obj -b my-bucket -k my-file.txt 
  -v 'arbitrary characters to convert to bytes format'
  
  NOTE: Following three command line arguments can be added to any 
    command in order to control IAM credentials used to access AWS:
    -i '20AlphNumChars' -s '40AlphaNumCharAnd/+' -e 'us-east-1'
  

  NOTE: First parameter (i.e., action) is required; others optional.
  >>> import s3_man
  >>> s3_man.s3_man('create_s3', bucket_name='my-bucket')
  >>> s3_man.s3_man('create_s3', bucket_name='my-bucket', 
                     region='us-east-1')
  >>> s3_man.s3_man('delete_s3', bucket_name='my-bucket')
  >>> s3_man.s3_man('list_s3')
  >>> s3_man.s3_man('list_s3', region='us-east-1')
  >>> s3_man.s3_man('list_s3_objs', bucket_name='my-bucket')
  >>> s3_man.s3_man('delete_s3_obj', bucket_name='my-bucket', 
                     key='my-object')
  >>> s3_man.s3_man('add_s3_obj', bucket_name='my-bucket', 
        key='my-object', file='C:\\my-file.txt')
  >>> bytes_data = b'arbitrary characters in bytes format'
  >>> s3_man.s3_man('add_s3_obj', bucket_name='my-bucket', 
        key='my-object', value=bytes_data
  
  NOTE: Following three parameters can be added to any function
    call in order to control IAM credentials used to access AWS: 
    id=access-key-id-to-use, secret=secret-access-key-to-use, 
    endpoint=endpoint-to-use
         
Dependencies:
  argparse
  logging
  re
  boto3
  botocore.exception.ClientError
  s3_list
"""
import argparse
import logging
import re
import boto3
from   botocore.exceptions import ClientError
from   io                  import IOBase
import s3_list

__all__        = ['s3_man']
custom_session = None
logging.basicConfig(filename='s3_man.log',level=logging.INFO)


def _valid_ipv4_address(address):
  """ Verify arg is valid IPv4 address; between 0.0.0.0 and 
  255.255.255.255.  Failing test returns either 'None' or 'False'
  """
  #legal chars limited to numbers (i.e., 0 - 255) and '.'
  RE_MATCH_OCTECT = r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
  RE_MATCH_VALID_ADDR = (r'\b' 
                             + RE_MATCH_OCTECT 
                             + r'\.'
                             + RE_MATCH_OCTECT 
                             + r'\.'
                             + RE_MATCH_OCTECT 
                             + r'\.'
                             + RE_MATCH_OCTECT 
                       + r'\b')
     
  return((re.match(RE_MATCH_VALID_ADDR, address)) and
         (address.count('.') == 3))  #ensure exactly four octets


def _similar_to_ipv4_address(address):
  """ Verify arg in IPv4 format; between 0.0.0.0 - 999.999.999.999
  """
  #legal characters limited to numbers and '.'
  if(re.match(r'^[0-9.]+$', address)):
    if(address.count('..') < 1):
      if(address.count('.') == 3):   #ensure exactly four octects
        return(True)

  return(False)  

  
def _validate_s3_name_format(bucket_name):
  """ NOTE: uses naming standard starting 3/2018; us-east-1 no longer 
  accepts upper case letters and underscores for creating new buckets.
  """
  if((len(bucket_name) > 2) and (len(bucket_name) < 64)):
    if((bucket_name[0].isalnum()) and (bucket_name[-1].isalnum())):
      if(bucket_name == bucket_name.lower()):
        #legal chars limted to alphanumeric, '-', '.'
        if(re.match(r'^[a-z0-9.-]+$', bucket_name)):
          #in case name is composed of labels, catch invalid labels
          if((not '..' in bucket_name) and 
             (not '-.' in bucket_name) and 
             (not '.-' in bucket_name)):
            if((not _valid_ipv4_address(bucket_name)) and
               (not _similar_to_ipv4_address(bucket_name))):
              return(True)
  return(False)


def _validate_s3_obj_name_format(object_name):
  """ ensure arg is str or unicode that is no longer than 1024
  """
  is_valid = False
  
  if(object_name):
    if(((isinstance(object_name, str)) or (isinstance(object_name, unicode)))
        and len(object_name) < 1025):
      is_valid = True
  return(is_valid)


def _create_custom_session(id, key, endpoint):
  """ Attempt to create a custom boto3 session to overide use of the 
  default profile located in the ".aws/credentials" file. 
  """
  global custom_session
  custom_session = None
  if(id.isalnum and (len(id)  == 20)):
    if(re.match(r'^[A-Za-z0-9/+]*$', key) and (len(key) == 40)):
      region = s3_list.validate_region(endpoint)
      if(not region):
        region = 'us-east-1'
      
      try:
        custom_session = boto3.Session(aws_access_key_id= id, 
                                       aws_secret_access_key= key,
                                       region_name= region) 
      except Exception as e:
        custom_session = None
        logging.error(f'Boto3 exception thrown: {e}') 


def _does_obj_exist(bucket_name, object_name):
  """ Does an object exist in a bucket?  Returns True or False.  A False could
  indicate that the object does not exist or that the IAM key pair used to 
  create the boto3 session does not have access permission to the bucket.
  """
  global custom_session
  results = True
  
  try:
    if(custom_session is None):
      s3_access = boto3.resource('s3')
    else:
      s3_access = custom_session.resource('s3')
    s3_access.Object(bucket_name, object_name).load()
  except ClientError as e:
    error_code = int(e.response['Error']['Code'])
    if(error_code == 404):
      results = False
  except Exception as e:
    results = False
    logging.error(f'Boto3 exception thrown: {e}')  
    
  return(results)


def _does_bucket_exist(bucket_name):
  """ Does an S3 bucket exist?  Returns True or False.  A False could 
  indicate that the bucket does not exist or that the IAM key pair
  used to create the boto3 session does not have access permission to 
  the bucket.
  """
  global custom_session
  results = True

  try:
    if(custom_session is None):
      s3_access = boto3.client('s3')
    else:
      s3_access = custom_session.client('s3')
    s3_access.head_bucket(Bucket=bucket_name)
  except ClientError as e:
    error_code = int(e.response['Error']['Code'])
    if(error_code == 404):
      results = False
  except Exception as e:
    results = False
    logging.error(f'Boto3 exception thrown: {e}')    
 
  return(results)
  

def _create_s3(bucket_name, key, file, value, region, id, secret, endpoint):
  """ Create bucket using 'bucket_name' in specified region if a valid
  region is supplied in the region argument.
  
  Due to s3_man() method of translating command line input into a function
  call, all functions sent all parameters.  This function does not use:
  key, file, value, id, secret, endpoint
  """
  global custom_session
  result = f'The bucket named "{bucket_name}" '
 
  if((bucket_name) and (_validate_s3_name_format(bucket_name))):
    if(not _does_bucket_exist(bucket_name)):
      try:
        if(custom_session is None):
          s3_access = boto3.resource('s3')     
        else:
          s3_access = custom_session.resource('s3')
        location = s3_list.validate_region(region)
        if(location):
          new_bucket = s3_access.create_bucket(
                         Bucket=bucket_name, CreateBucketConfiguration=
                         {'LocationConstraint': location})                       
        else:
          new_bucket = s3_access.create_bucket(Bucket=bucket_name)
        new_bucket.wait_until_exists()
        result += 'was created.'        
      except Exception as e:
        logging.error(f'Boto3 exception thrown: {e}')
        result += 'could not be created.'        
    else:
      result = f'A bucket named "{bucket_name}" already exists.'
      logging.error(result) 
  else:
    result = 'An empty or invalid bucket_name argument was supplied.'
    logging.error(result)

  return(result)
  
  
def _delete_s3(bucket_name, key, file, value, region, id, secret, endpoint):
  """ Delete the bucket indicated by 'bucket_name' argument.  Returns
  message indicating success or that the bucket_name argument is invalid
  or that the bucket could not be deleted (most likely indicating that 
  the IAM key pair used to create the boto3 session does not have access 
  permissions to the specified bucket.
  
  Due to s3_man() method of translating command line input into a function
  call, all functions sent all parameters.  This function does not use:
  key, file, value, region, id, secret, endpoint
  """
  global custom_session
  result = f'The bucket named {bucket_name} '
  
  if((bucket_name) and (_validate_s3_name_format(bucket_name))):
    if(_does_bucket_exist(bucket_name)):
      try:
        if(custom_session is None): 
          s3_access = boto3.resource('s3') 
        else:
          s3_access = custom_session.resource('s3')                     
        bucket = s3_access.Bucket(bucket_name)  
        object_count = sum(1 for _ in bucket.objects.all())
        if(object_count > 0):
          result += 'is not empty.  Could not be deleted.'
        else:
          bucket = s3_access.Bucket(bucket_name)
          bucket.delete()
          bucket.wait_until_not_exists()
          result += 'was deleted.'
      except Exception as e:
        result += 'could not be deleted.'  
        logging.error(f'Boto3 exception thrown: {e}') 
    else:
      result += 'does not exist.'
      logging.error(result)    
  else:
    result = 'Empty or invalid bucket name was supplied.'
    logging.error(result)

  return(result)


def _list_s3(bucket_name, key, file, value, region, id, secret, endpoint):
  """ Return comma separated list of S3 buckets for specified region
  or literatl string 'No buckets located...'  If 'region' arg is not a
  valid region identifier, return list of s3 buckets across all 
  regions. 
  
  Due to s3_man() method of translating command line input into a function
  call, all functions sent all parameters.  This function does not use:
  bucket_name, key, file, and value
  """
  return(s3_list.s3_list(region, id=id, secret=secret, endpoint=endpoint ))
  
  
def _list_s3_objs(bucket_name, key, file, value, region, id, secret, endpoint):
  """ Returns string of comma separated object names, an empty string, or
  the contents of a boto3 exception (most likely indicating that the IAM
  key pair used to create the boto3 session does not have access permissions
  to the specified bucket.
  
  Due to s3_man() method of translating command line input into a function
  call, all functions sent all parameters.  This function does not use:
  file, key, value, region, id, secret, endpoint
  """
  global custom_session
  obj_list = ''

  if((bucket_name) and (_validate_s3_name_format(bucket_name))):
    if(_does_bucket_exist(bucket_name)):
      try:
        if(custom_session is None):       
          s3_access = boto3.resource('s3')
        else:
          s3_access = custom_session.resource('s3')
        bucket = s3_access.Bucket(bucket_name)
        for obj in bucket.objects.all():
          obj_list += obj.key + ', '
      except Exception as e:
        obj_list = f'Boto3 exception thrown: {e}'
        logging.error(obj_list) 
    else:
      obj_list = f'A bucket named {bucket_name} does not exist'
      logging.error(obj_list)
  else:
    obj_list = 'Empty or invalid bucket name was supplied.'
    logging.error(obj_list)
  
  if(not(obj_list)):
    obj_list = f'The bucket {bucket_name} is empty.'
  elif(obj_list.endswith(', ')):
    obj_list = f'The objects in {bucket_name} are: ' + obj_list[:-2]
  
  return(obj_list)


def _delete_s3_obj(bucket_name, key, file, value, region, id, secret, endpoint):
  """ Delete specified object from the specified bucket. Returns a message
  indicating success or one of a number of error messages.  The error message
  containing "...could not be deleted..." could indicate that the IAM key
  pair used to create the boto3 session does not have sufficient permission.
  
  Due to s3_man() method of translating command line input into a function
  call, all functions sent all parameters.  This function does not use:
  file, value, region, id, secret, endpoint
  """
  global custom_session
  result = ''
  
  if((bucket_name) and (_validate_s3_name_format(bucket_name))):
    if(_does_bucket_exist(bucket_name)):
      if(_validate_s3_obj_name_format(key)):
        if(_does_obj_exist(bucket_name, key)):
          try:
            if(custom_session is None):
              s3_access = boto3.resource('s3')   
            else:
              s3_access = custom_session.resource('s3')
            the_object = s3_access.Object(bucket_name, key)
            the_object.delete()
            the_object.wait_until_not_exists()
            result = f'The object named "{key}" was successfully deleted from '
            result += f'the bucket named "{bucket_name}".'
          except Exception as e:
            result = f'The object named "{key}" could not be deleted from the '
            result += f'bucket named {bucket_name}.'
            logging.error(f'Boto3 exception thrown: {e}')
        else:
          result = f'Either the object named "{key}" does not exist or '
          result += 'insufficient privilege to access the bucket named '
          result += f'"{bucket_name}".'
          logging.error(result)
      else:
        result = 'The "key" argument, indicating object to delete, is invalid.'
        logging.error(result)
    else:
      result = f'A bucket named "{bucket_name}" does not exist.'
      logging.error(result)
  else:
    result = 'The "bucket_name" argument is either empty or invalid.'
    logging.error(result)
    
  return(result)
  
  
def _set_object_data(file, value):
  """ Return the 'object_data' parameter to use in boto3 call
  "s3.put_object('bucket_name', 'object_key', 'object_data')"
  
  'object_data' can be hold either a Python bytes value or 
  a Python <ioBufferedReader> object connected to the file to
  upload as the value of the new S3 object.  None is returned
  if the argument is invalid or an exception occurs.
  """
  object_data = None
    
  if(file or value):
    if (value):
      object_data = value
    else:
      try:
        object_data = open(file, 'rb')
      except Exception as e:
        logging.error(f'Boto3 exception thrown: {e}')
        object_data = None
  else:
    logging.error('Either a file to upload or a bytes value for new S3 ' +
                  'object must be specified')
  
  return(object_data)

  
def _add_s3_obj(bucket_name, key, file, value, region, id, secret, endpoint):
  """ Upload an object to a bucket. The'region'
  
  NOTE: A preexisting object will be over written if you specify an 
  object key that matches a preexisting object.  This is consistent 
  with AWS CLI behavior.
  
  Due to s3_man() method of translating command line input into a function
  call, all functions sent all parameters.  This function does not use:
  region, id, secret, endpoint arguments
  
  NOTE: the file paramter or value parameter or neither will be passed in
  """
  global custom_session
  result = ''
  if((bucket_name) and (_validate_s3_name_format(bucket_name))):
    if(_does_bucket_exist(bucket_name)):
      if(_validate_s3_obj_name_format(key)):
        object_data = _set_object_data(file, value)
        if(object_data):
          try:
            if(custom_session is None):
              s3_access = boto3.resource('s3')
            else:
              s3_access = custom_session.resource('s3')
            the_bucket = s3_access.Bucket(bucket_name)
            the_object = the_bucket.put_object(Key=key, Body=object_data)
            the_object.wait_until_exists()   
            result = f'An object named "{key}" was successfully added to the '
            result += f'bucket named "{bucket_name}".'            
          except Exception as e:
            result = f'The object named "{key}" could not be added to the '
            result += f'bucket named "{bucket_name}".' 
            logging.error(f'Boto3 exception thrown: {e}')        
          
          if(isinstance(object_data, IOBase)):
            if(not object_data.closed):
              object_data.close() 
        else:
          result = 'Either the file argument or the value argument is invalid.'
          logging.error(result)
      else:
        result = 'Argument supplied for new object key is invalid.'
        logging.error(result)    
    else:
      result = f'A bucket named "{bucket_name}" does not exist'
      logging.error(result)
  else: 
    result = 'Argument supplied for bucket name is invalid.'
    logging.error(result)
    
  return(result)  
  
  
def s3_man(action, bucket_name='', key='', file='', value='', region='',
           id='', secret='', endpoint=''):
  """
  Args:
    action  (str):        Required. Can be: 'create_s3', 'delete_s3', 
                            'list_s3', 'list_s3_objs', or 'delete_s3_obj'
    bucket  (str):        Optional. S3 bucket to apply the command to 
    key     (str):        Optional. Key of S3 object to apply command to
    file    (str):        Optional. File to upload as new S3 object
    value   (str/bytes):  Optional. Bytes value, or string to turn into 
                            bytes value, as contents for new S3 object
    region  (str):        Optional. Region to apply command in
    id (str):             Optional. AWS access key id for authorization
    secret(str):          Optional. AWS secret access key for auth
    endpoint(str):        Optional. Regional endpoint for AWS API calls
    
    NOTE: user will be allowed to supply the 'file' argument, the 'value'
      argument, or neither; supplying both arguments not allowed.
  
  Returns:
    (str): list of S3 buckets or list of objects in the bucket or 
           a success / failure message for command execution
  """
  global custom_session
  COMMANDS = {'create_s3' :     _create_s3, 
              'delete_s3' :     _delete_s3, 
              'list_s3' :       _list_s3,
              'list_s3_objs' :  _list_s3_objs, 
              'delete_s3_obj' : _delete_s3_obj,
              'add_s3_obj' :    _add_s3_obj 
             } 
  result = '' 
  
  if( isinstance(action, str) and isinstance(bucket_name, str) and 
      isinstance(key, str) and (isinstance(file, str)) and
      ((isinstance(value, bytes)) or (isinstance(value, str))) and 
      isinstance(region, str) and isinstance(id, str) and 
      isinstance(secret, str) and isinstance(endpoint, str) ):  

    if(not (file and value)):

      # For value argument supplied at OS prompt, convert to bytes value
      if((value) and (isinstance(value, str))):
        value = bytes(value, 'utf-8') 
    
      if(action):         
        action = action.lower()
        if(action in COMMANDS):
          if(id and secret):
            _create_custom_session(id, secret, endpoint)     
          result = COMMANDS[action](bucket_name, key, file, value, region, id, 
                                    secret, endpoint)
        else:
          result = 'Action argument supplied is invalid'
          logging.error(result)
      else:
        result = 'No argument supplied to indicate desired action'
        logging.error(result)
    else:
      result = ('You can specify a file to upload or a bytes value for new ' +
                'S3 object but not both')
      logging.error(result)
  else:
    result = 'One or more arguments was of an invalid type'
    logging.error(result)
    
  custom_session = None
  return(result)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
    description = 'manage S3 buckets / objects')
  parser.add_argument('action', type=str, 
                      help= 'specify action to take on bucket/object')
  parser.add_argument('-b', '--bucket', type=str,
                      help='specify bucket for this action')
  parser.add_argument('-k', '--key', type=str,
                      help='specify key for this action')
  parser.add_argument('-f', '--file', type=str,
                      help='specify file name for this action')
  parser.add_argument('-v', '--value', type=str,
                      help='specify binary value for this action')                        
  parser.add_argument('-r', '--region', type=str,
                      help='specify region for this action')
  parser.add_argument('-i', '--id', type=str,
                      help='specify access key id to authorize access')
  parser.add_argument('-s', '--secret', type=str,
                      help='specify secret access key to authorize access')
  parser.add_argument('-e', '--endpoint', type=str,
                      help='specify which AWS regional endpoint to use')                      
  args = parser.parse_args() 
  
  convert_None = lambda arg: '' if arg is None else arg 
 
  print(s3_man(args.action, convert_None(args.bucket), convert_None(args.key),
               convert_None(args.file), convert_None(args.value), 
               convert_None(args.region), convert_None(args.id), 
               convert_None(args.secret), convert_None(args.endpoint)))