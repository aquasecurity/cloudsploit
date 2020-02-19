var assert = require('assert');
var expect = require('chai').expect;
var s3 = require('./bucketEncryption');

const createCache = (cmk, bucketErr, sseAes, kms) => {
    var bucketObj = {};

    if (bucketErr) {
        bucketObj = {
            "err": {
              "message": "The server side encryption configuration was not found",
              "code": "ServerSideEncryptionConfigurationNotFoundError"
            }
        };
    } else if (sseAes) {
        bucketObj = {
            "data": {
              "ServerSideEncryptionConfiguration": {
                "Rules": [
                  {
                    "ApplyServerSideEncryptionByDefault": {
                      "SSEAlgorithm": "AES256"
                    }
                  }
                ]
              }
            }
        };
    } else if (kms) {
        bucketObj = {
            "data": {
              "ServerSideEncryptionConfiguration": {
                "Rules": [
                  {
                    "ApplyServerSideEncryptionByDefault": {
                      "SSEAlgorithm": "aws:kms",
                      "KMSMasterKeyID": "arn:aws:kms:us-east-1:0123456789101:key/abc0123"
                    }
                  }
                ]
              }
            }
        };
    }

    return {
      "kms": {
        "listKeys": {
          "us-east-1": {
            "data": [
              {
                "KeyId": "abc0123",
                "KeyArn": "arn:aws:kms:us-east-1:0123456789101:key/abc0123"
              }
            ]
          }
        },
        "describeKey": {
          "us-east-1": {
            "abc0123": {
              "data": {
                "KeyMetadata": {
                  "KeyId": "abc0123",
                  "Arn": "arn:aws:kms:us-east-1:0123456789101:key/abc0123",
                  "Description": cmk ? "My key" : "Default master key that protects my S3 objects when no other key is defined",
                  "KeyManager": cmk ? "CUSTOMER" : "AWS"
                }
              }
            }
          }
        }
      },
      "s3": {
        "listBuckets": {
          "us-east-1": {
            "data": [
              {
                "Name": "bucket1"
              }
            ]
          }
        },
        "getBucketEncryption": {
          "us-east-1": {
            "bucket1": bucketObj
          }
        }
      }
    };
};

describe('bucketEncryption', function () {
    describe('run', function () {
        it('should give failing result if S3 bucket has no encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has encryption disabled')
                done()
            };

            const cache = createCache(false, true, false, false);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has AES encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has AES256 encryption enabled')
                done()
            };

            const cache = createCache(false, false, true, false);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has AWS KMS encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled')
                done()
            };

            const cache = createCache(false, false, false, true);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has CMK KMS encryption', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled')
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if unencrypted S3 bucket matches whitelist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('is whitelisted via custom setting')
                done()
            };

            const cache = createCache(false, true, false, false);

            s3.run(cache, {
              s3_encryption_allow_pattern: '^bucket1$'
            }, callback);
        })

        it('should give failing result if unencrypted S3 bucket does not match whitelist', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has encryption disabled')
                done()
            };

            const cache = createCache(false, true, false, false);

            s3.run(cache, {
              s3_encryption_allow_pattern: '^bucket2$'
            }, callback);
        })

        it('should give failing result if S3 bucket has AES encryption with opt-out', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('but is not using a CMK')
                done()
            };

            const cache = createCache(false, false, true, false);

            s3.run(cache, {s3_encryption_require_cmk: 'true'}, callback);
        })

        it('should give failing result if S3 bucket has AWS KMS encryption with opt-out', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('but is not using a CMK')
                done()
            };

            const cache = createCache(false, false, false, true);

            s3.run(cache, {s3_encryption_require_cmk: 'true'}, callback);
        })

        it('should give passing result if S3 bucket has CMK KMS encryption with opt-out', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has aws:kms encryption enabled')
                done()
            };

            const cache = createCache(true, false, false, true);

            s3.run(cache, {s3_encryption_require_cmk: 'true'}, callback);
        })
    })
});