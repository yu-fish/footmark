# encoding: utf-8
"""
Represents a connection to the OSS service.
"""

from footmark.oss.connection import OSSConnection
import oss2


class Bucket(OSSConnection): 
    """ 
    Object Storage Services
    """

    def __init__(self, acs_access_key_id=None, acs_secret_access_key=None,
                 region=None, bucket_name=None):
        """
        Init method to create a new bucket object.
        """
        super(Bucket, self).__init__(acs_access_key_id, acs_secret_access_key, region)
        self.bucket_name = bucket_name
        self.bucket = oss2.Bucket(self.auth, self.endpoint, self.bucket_name)
        self.service = oss2.Service(self.auth, self.endpoint)

    def create_bucket(self, permission):
        """
        Create a New Bucket
        :type permission: str
        :param permission: This option lets the user set the canned permissions on the bucket that are created
        :return: Details of newly created bucket
        """
        changed = False
        results = []

        try:
            bucket_list, result = self.list_bucket(prefix=self.bucket_name)
            if self.bucket_name in bucket_list:
                results.append("Error, Bucket with same name already exist.")
            else:   
                response = self.make_oss_request(lambda: self.bucket.create_bucket(permission))
                results.append("Bucket Created Successfully")
                if type(response) is oss2.models.RequestResult:
                    results.append({"RequestId": str(response.request_id),
                                    "Url": str(response.resp.response.request.url)})
                changed = True
        except Exception as ex:
            details = self.error_handler(ex)
            results.append("Error in creating bucket " + self.bucket_name + ". Details: " + details)

        return changed, results

    def delete_bucket(self):
        """
        Delete a Bucket
        :return: Returns status of operation
        """
        changed = False
        results = []

        try:
            # List all the objects of Bucket
            oss_object_list = self.make_oss_request(lambda: self.list_bucket_objects())

            # If delete all objects from bucket
            if (type(oss_object_list[0]) is list) and len(oss_object_list[0]) > 0:
                delete_obj_result = self.make_oss_request(
                    lambda: self.delete_bucket_objects(objects=oss_object_list[0]))

            #  Delete bucket
            response = self.make_oss_request(lambda: self.bucket.delete_bucket()) 
            results.append("Bucket Deleted Successfully") 
            if type(response) is oss2.models.RequestResult:
                results.append({"RequestId": str(response.request_id)})
            changed = True
        except Exception as ex:
            details = self.error_handler(ex)
            results.append("Error in deleting bucket " + self.bucket_name + ". Details: " + details)

        return changed, results

    def simple_upload(self, expiration=None, headers=None, encrypt=None, metadata=None, overwrite=None, src=None,
                      file_name=None):
        """
        Upload a file to Bucket
        :type expiration: int
        :param expiration: Time limit (in seconds) for the URL generated and returned by OSS
        :type headers: dict
        :param headers: Custom headers for PUT operation 
        :type encrypt: str
        :param encrypt: When set for PUT mode, asks for server-side encryption
        :type metadata: dict
        :param metadata: Metadata for PUT operation, as a dictionary of 'key=value' and 'key=value,key=value'
        :type overwrite: str
        :param overwrite: Force overwrite either locally on the filesystem or remotely with the object/key
        :type src: str
        :param src: The source file path when performing a PUT operation
        :type file_name: str
        :param file_name: Name of after upload to bucket
        :return: Details of uploaded file in bucket
        """
        changed = False
        results = []

        if headers is None:
            headers_data = {}
        else:
            headers_data = headers

        if (expiration is not None) and (type(expiration) is int):
            headers_data.update({"Expires": str(expiration)})

        if metadata is not None:
            for key, value in metadata.items():
                if (key is not None) and (value is not None):
                    headers_data.update({key: value})
        try:
            # Open file in binary read mode
            with open(src, 'rb') as f:
                response = self.make_oss_request(lambda: self.bucket.put_object(
                    key=file_name, data=f, headers=headers_data))
            results.append("File uploaded Successfully")
            if type(response) is oss2.models.PutObjectResult:
                results.append({"RequestId": str(response.request_id), "Url": str(response.resp.response.url)})
            changed = True
        except Exception as ex:
            if type(ex) is IOError:
                results.append({"Error message": str(ex.args[1])})
            else:
                details = self.error_handler(ex)
                results.append("Error in uploading file in bucket " + self.bucket_name + ". Details: " + details)

        return changed, results

    def create_folder(self, folder_name):
        """
        Creates folder in existing bucket
        :type folder_name: str
        :param folder_name: folder_name to be created        
        :return: changed value and result
        """

        changed = False
        results = []

        try:
            # Creates folder in bucket
            response = self.make_oss_request(lambda: self.bucket.put_object(key=folder_name, data=''))
            changed = True
            results.append("Folder Created Successfully")
        except Exception as e:
            details = self.error_handler(e)
            results.append("Error in folder creation for bucket " + self.bucket_name + ". Details: " + details)

        return changed, results

    def list_bucket_objects(self, marker="", max_keys=100):
        """
        Lists Bucket Objects
        :type marker: str
        :param marker: the key to start with when using list mode. Object keys are returned in alphabetical order, 
         starting with key after the marker in order.
        :type max_keys: int
        :param max_keys: Max number of results to return in list mode
        :return: list of retrieved keys and result
        """

        results = []
        keys = []

        if max_keys is None:
            max_keys = 100

        try:
            response = self.make_oss_request(lambda: self.bucket.list_objects(marker=marker, max_keys=max_keys))

            bucket_objects = response.object_list
            if len(bucket_objects) > 0:
                keys = [object.key for object in bucket_objects]
                results.append("Bucket objects retrieved successfully")
            else:
                results.append("No objects found for the bucket")

        except Exception as e:
            details = self.error_handler(e)
            results.append("Error in listing bucket objects for bucket " + self.bucket_name + ". Details: " + details)

        return keys, results

    def delete_bucket_objects(self, objects):
        """
        Delete Objects in Bucket
        :type objects: list
        :param objects: objects to delete in bucket
        :return: changed value and result
        """
        results = []
        changed = False

        try:
            response = self.make_oss_request(lambda: self.bucket.batch_delete_objects(objects))
            results.append("Objects deleted successfully")
            changed = True
        except Exception as e:
            details = self.error_handler(e)
            results.append("Error in deleting bucket objects for bucket " + self.bucket_name + ". Details: " + details)

        return changed, results

    def object_exists(self, key):
        """
        Verify if object exists in Bucket
        :type key: str
        :param key: object key to verify for existence
        :return: boolean value representing object existence and error details if any
        """

        try:
            object_exists = self.make_oss_request(lambda: self.bucket.object_exists(key))
            return object_exists, None
        except Exception as e:
            details = self.error_handler(e)
            return False, details

    def list_bucket(self, prefix="", marker="", max_keys=100):
        """   
        List all Buckets   
        :type prefix: str
        :param prefix: prefix to search bucket
        :type marker: str
        :param marker: the key to start with when using list mode. 
          Object keys are returned in alphabetical order, starting 
          with key after the marker in order.
        :type max_keys: int
        :param max_keys: Max number of results to return in list mode
        :return: Returns list of Buckets
        """

        results = []
        keys = []

        if max_keys is None:
            max_keys = 100

        try:
            response = self.make_oss_request(lambda: self.service.list_buckets(
                prefix=prefix, marker=marker, max_keys=max_keys))

            if type(response) is oss2.models.ListBucketsResult:
                bucket_list = response.buckets
                if len(bucket_list) > 0:
                    keys = [bucket_obj.name for bucket_obj in bucket_list]
                    results.append("Bucket retrieved successfully")
                else:
                    results.append("No buckets found")

        except Exception as e:
            details = self.error_handler(e)
            results.append("Error in listing buckets. Details: " + details)

        return keys, results



