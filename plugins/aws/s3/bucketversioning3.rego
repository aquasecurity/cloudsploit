package s3.bucketversioning

__rego_metadata__ := {
    "id": "XYZ-1234",
    "title": "bucketversioning3",
    "version": "v1.0.0",
    "severity": "HIGH",
    "category": "S3",
    "description": "Ensures object versioning is enabled on S3 buckets",
    "apis": ["S3:getBucketVersioning", "S3:listBuckets", "S3:getBucketLocation"],
    "rules": {
                "2": "data.s3.bucketversioning.fail",
                "0": "data.s3.bucketversioning.pass"
              }
}
#-
# buckets for what status is Suspended
fail[res] {
	input.data.Status
	versioning := input.data.Status
	versioning == "Suspended"
	res := {
	    "msg": "Bucket has versioning disabled",
	    "status": 2
	}
}

# Buckets for what no status,that means versioning is disabled
fail[res]  {
	not input.data.Status
    res := {
    	    "msg": "Bucket has versioning disabled",
    	    "status": 2
    	}
}

# s3 buckets with versioning enabled
pass[res] {
	input.data.Status
	versioning := input.data.Status
	versioning == "Enabled"
	 res := {
        	    "msg": "Bucket has versioning enabled",
        	    "status": 0
        	}
}
