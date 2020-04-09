var assert = require('assert');
var expect = require('chai').expect;
var defaultEncryption = require('./ssmEncryptedParameters.js')

const createCache = (paramInfo, keyInfo) => {
    return {
        sts: {
            getCallerIdentity: {
                "us-east-1": {
                    data: "1234567890"
                }
            }
        },
        ssm: {
            describeParameters: {
                'us-east-1': paramInfo
            }
        },
        kms: {
            describeKey: {
                'us-east-1': keyInfo
            },
            listAliases: {
                'us-east-1': {
                    data : [
                        {
                            AliasName: "alias/myAlias",
                            TargetKeyId: "abcdefgh-1234-12ab-12ab-012345678910"
                        }
                    ]
                }
            }
        }
    }
}

const createDataHolder = (resource, data) => {
    returnVal = {}
    returnVal[resource] = data
    return returnVal
}

var ssmUnencrypted = {
    "Name": "/String/Alias",
    "Type": "String",
    "LastModifiedDate": "2019-05-06T20:00:15.917Z",
    "LastModifiedUser": "arn:aws:sts::1234567890:assumed-role/abc-role/role123",
    "Version": 1,
    "Tier": "Standard",
    "Policies": []
}

var ssmEncryptedAlias = {
    "Name": "/String/Alias",
    "Type": "SecureString",
    "KeyId": "alias/myAlias",
    "LastModifiedDate": "2019-05-06T20:00:15.917Z",
    "LastModifiedUser": "arn:aws:sts::1234567890:assumed-role/abc-role/role123",
    "Version": 1,
    "Tier": "Standard",
    "Policies": []
}

var ssmEncryptedArn = {
    "Name": "/String/Alias",
    "Type": "SecureString",
    "KeyId": "arn:aws:kms:us-east-1:454679818906:key/abcdefgh-1234-12ab-12ab-012345678910",
    "LastModifiedDate": "2019-05-06T20:00:15.917Z",
    "LastModifiedUser": "arn:aws:sts::1234567890:assumed-role/abc-role/role123",
    "Version": 1,
    "Tier": "Standard",
    "Policies": []
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

// todo fix copy/paste errors "parameters"

describe('ssmEncryptedParameters', function () {
    var awsKey = "abcdefgh-1234-12ab-12ab-012345678910"
    describe('run', function () {
        describe('noSettings', function() {
            it('should PASS when no ssm parameters exist.', function (done) {
                const cache = createCache({data: []}, {});

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`awskms\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`awskms\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`awscmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`awscmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when parameter has no encryption enabled.', function (done) {
                const cache = createCache({data: [ssmUnencrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when parameter has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {}, callback) })
            })
        });
        describe('awskmsSettings', function() {
            it('should PASS when no parameters exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`awskms\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`awskms\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`awscmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`awscmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when parameter has no encryption enabled.', function (done) {
                const cache = createCache({data: [ssmUnencrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when parameter has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awskms'}, callback) })
            })
        })
        describe('awscmkSettings', function() {
            it('should PASS when no parameters exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should WARN when the parameter \`awskms\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should WARN when the parameter \`awskms\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the parameter \`awscmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the parameter \`awscmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when parameter has no encryption enabled.', function (done) {
                const cache = createCache({data: [ssmUnencrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when parameter has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'awscmk'}, callback) })
            })
        })
        describe('externalcmkSettings', function() {
            it('should PASS when no parameters exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the parameter \`awskms\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the parameter \`awskms\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the parameter \`awscmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should WARN when the parameter \`awscmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the parameter \`externalcmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when parameter has no encryption enabled.', function (done) {
                const cache = createCache({data: [ssmUnencrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when parameter has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'externalcmk'}, callback) })
            })
        })
        describe('cloudhsmSettings', function() {
            it('should PASS when no parameters exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the parameter \`awskms\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the parameter \`awskms\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the parameter \`awscmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the parameter \`awscmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the parameter \`externalcmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should WARN when the parameter \`externalcmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(1)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should PASS when the parameter \`cloudhsm\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when parameter has no encryption enabled.', function (done) {
                const cache = createCache({data: [ssmUnencrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(2)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when parameter has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'cloudhsm'}, callback) })
            })
        })
        describe('misconfiguredSettings', function() {
            it('should FAIL when no parameters exist.', function (done) {
                const cache = createCache({data: []},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`awskms\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`awskms\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsKMSKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`awscmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`awscmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsCustomerKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`externalcmk\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`externalcmk\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsExternalKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`cloudhsm\` encryption enabled through Alias.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when the parameter \`cloudhsm\` encryption enabled through ARN.', function (done) {
                const cache = createCache({data: [ssmEncryptedArn]},
                    createDataHolder(awsKey, {data: awsHSMKey}))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when parameter has no encryption enabled.', function (done) {
                const cache = createCache({data: [ssmUnencrypted]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when parameter has an error.', function (done) {
                const cache = createCache(exampleAccessDeniedError,
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when kms encryption returns an error.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    createDataHolder(awsKey, exampleAccessDeniedError))

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })

            it('should FAIL when kms encryption does not exist.', function (done) {
                const cache = createCache({data: [ssmEncryptedAlias]},
                    {})

                const callback = (err, results) => {
                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(3)
                    done()
                }

                process.nextTick(() => { defaultEncryption.run(cache, {ssm_encryption_level: 'DNE'}, callback) })
            })
        })
    })
})