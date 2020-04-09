var assert = require('assert');
var expect = require('chai').expect;
var defaultEncryption = require('./rdsEncryption.js')

const createCache = (dbInfo, keyInfo) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': dbInfo
            }
        },
        kms: {
            describeKey: {
                'us-east-1': keyInfo
            }
        }
    }
}


const createDataHolder = (resource, data) => {
    returnVal = {}
    returnVal[resource] = data
    return returnVal
}

var rdsEncrypted = {//abbreviated event info
    "KmsKeyId": "arn:aws:kms:us-east-1:1234567890:key/abcdefgh-1234-12ab-12ab-012345678910",
    "DBInstanceArn": "arn:aws:rds:us-east-1:1234567890:db:myDB",
    "StorageEncrypted": true
}

var rdsNotEncrypted = {//abbreviated event info
    "KmsKeyId": "",
    "DBInstanceArn": "arn:aws:rds:us-east-1:1234567890:db:myDB",
    "StorageEncrypted": false
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

describe('rdsEncryption', function () {
    var dbInstance = "arn:aws:rds:us-east-1:1234567890:db:myDB"
    var awsKey = "abcdefgh-1234-12ab-12ab-012345678910"
    describe('run', function () {
        describe('noSettings', function() {
            it('should PASS when no instances exist', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    console.log(results)
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the instance \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the instance \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the instance \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the instance \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when instance has no encryption enabled.', function (done) {
                const cache = createCache({data: [rdsNotEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when instance has an error.', function (done) {
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

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })
        })
        describe('awskmsSettings', function() {
            it('should PASS when no instances exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the instance \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the instance \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the instance \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the instance \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when instance has no encryption enabled.', function (done) {
                const cache = createCache({data: [rdsNotEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when instance has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awskms'}, callback) })
            })
        })
        describe('awscmkSettings', function() {
            it('should PASS when no instances exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should WARN when the instance \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the instance \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the instance \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the instance \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when instance has no encryption enabled.', function (done) {
                const cache = createCache({data: [rdsNotEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when instance has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'awscmk'}, callback) })
            })
        })
        describe('externalcmkSettings', function() {
            it('should PASS when no instances exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the instance \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the instance \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the instance \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the instance \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when instance has no encryption enabled.', function (done) {
                const cache = createCache({data: [rdsNotEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when instance has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'externalcmk'}, callback) })
            })
        })
        describe('cloudhsmSettings', function() {
            it('should PASS when no instances exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the instance \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the instance \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the instance \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should PASS when the instance \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when instance has no encryption enabled.', function (done) {
                const cache = createCache({data: [rdsNotEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when instance has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'cloudhsm'}, callback) })
            })
        })
        describe('misconfiguredSettings', function() {
            it('should FAIL when no instances exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the instance \`awskms\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the instance \`awscmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the instance \`externalcmk\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the instance \`cloudhsm\` encryption enabled.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when instance has no encryption enabled.', function (done) {
                const cache = createCache({data: [rdsNotEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when instance has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [rdsEncrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {rds_encryption_level: 'DNE'}, callback) })
            })
        })
    })
})