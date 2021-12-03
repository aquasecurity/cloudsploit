var expect = require('chai').expect;
var projectArtifactsEncrypted = require('./projectArtifactsEncrypted');

const listProjects = [
    "testproj"             
];

const batchGetProjects = [
    {
        "projects": [
            {
            'name': 'testproj',
            'arn': 'arn:aws:codebuild:us-east-1:000011112222:project/testproj',
            'source': [Object],
            'secondarySources': [],
            'secondarySourceVersions': [],
            'artifacts': [Object],
            'secondaryArtifacts': [],
            'cache': [Object],
            'environment': [Object],
            'serviceRole': 'arn:aws:iam::000011112222:role/service-role/codebuild-testproj-service-role',
            'timeoutInMinutes': '60',
            'queuedTimeoutInMinutes': '480',
            'encryptionKey': 'arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250',
            'tags': [],
            'created': '2021-11-09T10:57:02.957Z',
            'lastModified': '2021-11-09T10:57:02.957Z',
            'badge': [Object],
            'logsConfig': [Object],
            'projectVisibility': 'PRIVATE'
            },
        ]
    },
    {
        "projects": [
            {
                'name': 'testproj',
                'arn': 'arn:aws:codebuild:us-east-1:000011112222:project/testproj',
                'source': [Object],
                'secondarySources': [],
                'secondarySourceVersions': [],
                'artifacts': [Object],
                'secondaryArtifacts': [],
                'cache': [Object],
                'environment': [Object],
                'serviceRole': 'arn:aws:iam::000011112222:role/service-role/codebuild-testproj-service-role',
                'timeoutInMinutes': '60',
                'queuedTimeoutInMinutes': '480',
                'encryptionKey': 'alias/aws/s3',
                'tags': [],
                'created': '2021-11-09T10:57:02.957Z',
                'lastModified': '2021-11-09T10:57:02.957Z',
                'badge': [Object],
                'logsConfig': [Object],
                'projectVisibility': 'PRIVATE'
            },
        ]
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
]

const createCache = (listProjects, keys, batchGetProjects, describeKey, listProjectsErr, keysErr, describeKeyErr, batchGetProjectsErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
    var projectName = (listProjects && listProjects.length) ? listProjects[0]: null;
    return {
        codebuild: {
            listProjects: {
                'us-east-1': {
                    err: listProjectsErr,
                    data: listProjects
                },
            },
            batchGetProjects: {
                'us-east-1': {
                    [projectName]: {
                        data: batchGetProjects,
                        err: batchGetProjectsErr
                    }
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('projectArtifactsEncrypted', function () {
    describe('run', function () {
        it('should PASS if CodeBuild project artifact is encrypted with desired encryption level', function (done) {
            const cache = createCache(listProjects, listKeys, batchGetProjects[0], describeKey[0]);
            projectArtifactsEncrypted.run(cache, { projects_artifact_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('CodeBuild project artifacts are encrypted with awscmk');
                done();
            });
        });

        it('should FAIL if CodeBuild project artifact is not encrypted with desired encryption level', function (done) {
            const cache = createCache(listProjects, listKeys, batchGetProjects[1], describeKey[1]);
            projectArtifactsEncrypted.run(cache, { projects_artifact_desired_encryption_level: 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('CodeBuild project artifacts are encrypted with awskms');
                done();
            });
        });

        it('should PASS if No CodeBuild projects artifact found', function (done) {
            const cache = createCache([]);
            projectArtifactsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No CodeBuild projects found');
                done();
            });
        });

        it('should UNKNOWN if unable to list project artifacts', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list project artifacts" });
            projectArtifactsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listProjects, null, null, null, { message: "Unable to list KMS keys" });
            projectArtifactsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})