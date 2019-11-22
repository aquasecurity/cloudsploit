var assert = require('assert');
var expect = require('chai').expect;
var defaultEncryption = require('./s3Encryption.js')

const createCache = (s3Buckets, encryptionData, keyData) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': s3Buckets
            },
            getBucketEncryption: {
                'us-east-1': encryptionData
            }
        },
        kms: {
            describeKey: {
                'us-east-1': keyData
            }
        }
    }
}

const createDataHolder = (resource, data) => {
    returnVal = {}
    returnVal[resource] = data
    return returnVal
}

var exampleBucket = {
    "Name" : "My-First-Bucket",
    "CreationDate" : "2018-02-07T20:51:31.000Z"
}

var exampleNoBucketEncryption = {
    "err": {
        "message": "The server side encryption configuration was not found",
        "code": "ServerSideEncryptionConfigurationNotFoundError",
        "region": null,
        "time": "2019-10-11T23:10:59.722Z",
        "requestId": "1234567896",
        "extendedRequestId": "1234567896",
        "statusCode": 403,
        "retryable": false,
        "retryDelay": 23.87272591244194
    }
}

var exampleAccessDeniedError = {
    "err": {
        "message": "Access Denied",
        "code": "AccessDenied",
        "region": null,
        "time": "2019-10-11T23:10:59.722Z",
        "requestId": "1234567896",
        "extendedRequestId": "1234567896",
        "statusCode": 403,
        "retryable": false,
        "retryDelay": 23.87272591244194
    }
}

var aes256Encryption = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }
}

var awsKMSEncryption = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "arn:aws:kms:us-east-1:1234567890:key/abcdefgh-1234-12ab-12ab-012345678910"
            }
        }]
    }
}

var awsKMSKey = { //abbreviated event
    "KeyMetadata": {
        "KeyManager": "AWS",
        "Origin": "AWS_KMS"
     }
}

var awsCustomerKey = { //abbreviated event
    "KeyMetadata": {
        "KeyManager": "CUSTOMER",
        "Origin": "AWS_KMS"
    }
}

var awsExternalKey = { //abbreviated event
    "KeyMetadata": {
        "KeyManager": "CUSTOMER",
        "Origin": "EXTERNAL"
    }
}

var awsHSMKey = { //abbreviated event
    "KeyMetadata": {
        "KeyManager": "CUSTOMER",
        "Origin": "AWS_CLOUDHSM"
    }
}

describe('bucketDefaultEncryptionSensitive', function () {
    var awsKey = "abcdefgh-1234-12ab-12ab-012345678910"
    var bucketName = "My-First-Bucket"
    describe('run', function () {
        describe('noSettings', function () {
            it('should PASS when no buckets exist.', function (done) {
                const cache = createCache({data: []},
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket has \`sse\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: aes256Encryption}),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket has more than \'sse\' encryption enabled, but describeKey has an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when that bucket has no encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleNoBucketEncryption),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when that bucket has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when bucket encryption returns an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleAccessDeniedError),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })
        })

        describe('sseSettings', function () {
            it('should PASS when no buckets exist.', function (done) {
                const cache = createCache({data: []},
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the bucket has \`sse\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: aes256Encryption}),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should PASS when the bucket \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should PASS when the bucket \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should PASS when the bucket \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should PASS when the bucket \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should PASS when the bucket has more than \'sse\' encryption enabled, but describeKey has an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should FAIL when that bucket has no encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleNoBucketEncryption),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should FAIL when that bucket has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })

            it('should FAIL when bucket encryption returns an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleAccessDeniedError),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'sse'}, callback) })
            })
        })

        describe('awskmsSettings', function () {
            it('should PASS when no buckets exist.', function (done) {
                const cache = createCache({data: []},
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should WARN when the bucket has \`sse\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: aes256Encryption}),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the bucket \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the bucket \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the bucket \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the bucket \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when describeKey has an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when that bucket has no encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleNoBucketEncryption),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when that bucket has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when bucket encryption returns an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleAccessDeniedError),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awskms'}, callback) })
            })
        })

        describe('awscmkSettings', function () {
            it('should PASS when no buckets exist.', function (done) {
                const cache = createCache({data: []},
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should WARN when the bucket has \`sse\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: aes256Encryption}),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should WARN when the bucket \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the bucket \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the bucket \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the bucket \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when describeKey has an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when that bucket has no encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleNoBucketEncryption),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when that bucket has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when bucket encryption returns an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleAccessDeniedError),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'awscmk'}, callback) })
            })
        })

        describe('externalcmkSettings', function () {
            it('should PASS when no buckets exist.', function (done) {
                const cache = createCache({data: []},
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should WARN when the bucket has \`sse\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: aes256Encryption}),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the bucket \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the bucket \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the bucket \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the bucket \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when describeKey has an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when that bucket has no encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleNoBucketEncryption),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when that bucket has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when bucket encryption returns an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleAccessDeniedError),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'externalcmk'}, callback) })
            })
        })

        describe('cloudhsmSettings', function () {
            it('should PASS when no buckets exist.', function (done) {
                const cache = createCache({data: []},
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should WARN when the bucket has \`sse\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: aes256Encryption}),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the bucket \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the bucket \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the bucket \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should PASS when the bucket \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when describeKey has an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, {data: awsKMSEncryption}),
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when that bucket has no encryption enabled.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleNoBucketEncryption),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when that bucket has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when bucket encryption returns an error.', function (done) {
                const cache = createCache({data: [exampleBucket]},
                    createDataHolder(bucketName, exampleAccessDeniedError),
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {s3_encryption_level: 'cloudhsm'}, callback) })
            })
        })
    })
})