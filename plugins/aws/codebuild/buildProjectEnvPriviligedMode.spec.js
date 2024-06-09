var expect = require('chai').expect;
const buildProjectEnvPriviligedMode = require('./buildProjectEnvPriviligedMode');

const listProjects = [
    'test-project'
];


const batchGetProjects = [
    {
        "projects": [
            {
                "name": "test-project",
                "arn": "arn:aws:codebuild:us-east-1:111122223333:project/test-project",
                "environment": {
                    "type": "ARM_CONTAINER",
                    "image": "aws/codebuild/amazonlinux2-aarch64-standard:2.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "environmentVariables": [],
                    "privilegedMode": true,
                    "imagePullCredentialsType": "CODEBUILD"
                },
            }
        ],
    },
    {
        "projects": [
            {
                "name": "test-project",
                "arn": "arn:aws:codebuild:us-east-1:111122223333:project/test-project",
                "environment": {
                    "type": "ARM_CONTAINER",
                    "image": "aws/codebuild/amazonlinux2-aarch64-standard:2.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "environmentVariables": [],
                    "privilegedMode": false,
                    "imagePullCredentialsType": "CODEBUILD"
                },
            }
        ],
    }
]

const createCache = (listProjects, batchGetProjects, listProjectsErr, batchGetProjectsErr) => {
    let project = (listProjects && listProjects.length) ? listProjects[0] : null;
    return {
        codebuild: {
            listProjects: {
                'us-east-1': {
                    data: listProjects,
                    err: listProjectsErr
                }
            },
            batchGetProjects: {
                'us-east-1': {
                    [project]: {
                        data: batchGetProjects,
                        err: batchGetProjectsErr
                    }
                }
            }
        }
    }
};

const createNullCache = () => {
    return {
        codebuild: {
            listProjects: {
                'us-east-1': { 'err': 'Error listing batchProjects' },
            },
        },
    };
};

describe('buildProjectEnvPriviligedMode', function () {
    describe('run', function () {

        it('should PASS if no CodeBuild projects found', function (done) {
            const cache = createCache([]);
            buildProjectEnvPriviligedMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No CodeBuild projects found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list codebuild project', function (done) {
            const cache = createNullCache();
            buildProjectEnvPriviligedMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list CodeBuild projects:');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to get CodeBuild project', function (done) {
            const cache = createCache(listProjects, null, null, { message: 'Unable to query CodeBuild project' });
            buildProjectEnvPriviligedMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query CodeBuild project:');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to get CodeBuild project', function (done) {
            const cache = createCache(listProjects, null, null, { message: 'Unable to query CodeBuild project' });
            buildProjectEnvPriviligedMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query CodeBuild project:');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CodeBuild project environment has privileged mode enabled', function (done) {
            const cache = createCache(listProjects, batchGetProjects[0], null, null);
            buildProjectEnvPriviligedMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('CodeBuild project environment has privileged mode enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if CodeBuild project environment has privileged mode disabled', function (done) {
            const cache = createCache(listProjects, batchGetProjects[1], null, null);
            buildProjectEnvPriviligedMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CodeBuild project environment has privileged mode disabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
