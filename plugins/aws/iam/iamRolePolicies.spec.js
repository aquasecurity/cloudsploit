var assert = require('assert');
var expect = require('chai').expect;
var iamRolePolicies = require('./iamRolePolicies');

function encodeCache(cache) {
    let copied_cache = JSON.parse(JSON.stringify(cache));
    let x;
    let data = [];
    for (x of copied_cache.iam.listRoles['us-east-1'].data) {
        x.AssumeRolePolicyDocument = encodeURIComponent(JSON.stringify(x.AssumeRolePolicyDocument));
        data.push(x);
    }
    copied_cache.iam.listRoles['us-east-1'].data = data;
    return copied_cache;
}

// apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:listAttachedRolePolicies','IAM:getRolePolicy'],
const cache =  {
        iam: {
            listRoles: {
                "us-east-1": {
                    data: [
                        {
                          AssumeRolePolicyDocument: {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": "arn:aws:iam::000000000000:root"
                                    },
                                    "Action": "sts:AssumeRole"
                                }
                              ]
                          },
                          RoleId: "AROAJ52OTH4H7LEXAMPLE",
                          CreateDate: "2013-05-11T00:02:27Z",
                          RoleName: "ExampleRole1",
                          Path: "/",
                          Arn: "arn:aws:iam::123456789012:role/ExampleRole1"
                        },
                        {
                          AssumeRolePolicyDocument: {
                            Version: "2012-10-17",
                            Statement: [
                              {
                                Action: "sts:AssumeRole",
                                Principal: {
                                  Service: "elastictranscoder.amazonaws.com"
                                },
                                Effect: "Allow",
                                Sid: ""
                              }
                            ]
                          },
                          RoleId: "AROAI4QRP7UFT7EXAMPLE",
                          CreateDate: "2013-04-18T05:01:58Z",
                          RoleName: "emr-access",
                          Path: "/",
                          Arn: "arn:aws:iam::123456789012:role/emr-access"
                        },
                    ]
                }
            },
            listRolePolicies: {
                "us-east-1": {
                  ExampleRole1: {
                    data: {
                      PolicyNames: ["a", "b"]
                    }
                  },
                  "emr-access": {
                    data: {
                      PolicyNames: ["c", "d"]
                    }
                  },
                }
            },
            listAttachedRolePolicies: {
                "us-east-1": {
                  ExampleRole1: {
                    data: {
                        AttachedPolicies: [
                            {PolicyName: "a", PolicyArn: "arn:aws:iam::aws:policy/a"},
                            {PolicyName: "b", PolicyArn: "arn:aws:iam::aws:policy/b"}
                        ],
                        IsTruncated: false,
                    }
                  },
                  "emr-access": {
                    data: {
                        AttachedPolicies: [
                            {PolicyName: "c", PolicyArn: "arn:aws:iam::aws:policy/c"},
                            {PolicyName: "d", PolicyArn: "arn:aws:iam::aws:policy/d"}
                        ],
                        IsTruncated: false,
                    }
                  }
                }
            },
            getRolePolicy: {
                "us-east-1": {
                    ExampleRole1: {
                        a: {
                            data: {
                                RoleName: "ExampleRole1",
                                PolicyDocument: {
                                    Statement: [
                                        {
                                            Action: [
                                                "s3:ListBucket",
                                                "s3:Put*",
                                                "s3:Get*",
                                                "s3:*MultipartUpload*"
                                            ],
                                            Resource: "*",
                                            Effect: "Allow",
                                            Sid: "1"
                                        }
                                    ]
                                },
                                PolicyName: "a"
                            }
                        },
                        b: {
                            data: {
                                RoleName: "ExampleRole1",
                                PolicyDocument: {
                                    Statement: [
                                        {
                                            Action: [
                                                "s3:ListBucket",
                                                "s3:Put*",
                                                "s3:Get*",
                                                "s3:*MultipartUpload*"
                                            ],
                                            Resource: "*",
                                            Effect: "Allow",
                                            Sid: "1"
                                        }
                                    ]
                                },
                                PolicyName: "b"
                            }
                        }
                    },
                    "emr-access": {
                        c: {
                            data: {
                                RoleName: "emr-access",
                                PolicyDocument: {
                                    Statement: [
                                        {
                                            Action: [
                                                "s3:ListBucket",
                                                "s3:Put*",
                                                "s3:Get*",
                                                "s3:*MultipartUpload*"
                                            ],
                                            Resource: "*",
                                            Effect: "Allow",
                                            Sid: "1"
                                        }
                                    ]
                                },
                                PolicyName: "c"
                            }
                        },
                        d: {
                            data: {
                                RoleName: "emr-access",
                                PolicyDocument: {
                                    Statement: [
                                        {
                                            Action: [
                                                "s3:*", //wildcard action
                                                "s3:Put*",
                                                "s3:Get*",
                                                "s3:*MultipartUpload*"
                                            ],
                                            Resource: "*",
                                            Effect: "Allow",
                                            Sid: "1"
                                        }
                                    ]
                                },
                                PolicyName: "d"
                            }
                        }
                    }
            }
            }
        }
    };


describe('iamRolePolicies', function () {
    describe('run', function () {
        it('should PASS when actions end with wildcard but ignore_service_specific_wildcards is enabled', function (done) {
            let settings = {
                ignore_service_specific_wildcards: true,
            };

            let callback = (err, results) => {
                expect(results[1].status).to.equal(0);
                done();
            };

            iamRolePolicies.run(encodeCache(cache), settings, callback)
        });

        it('should FAIL when action is literally *', function (done) {
            let settings = {};

            let copied_cache = JSON.parse(JSON.stringify(cache));
            copied_cache.iam.getRolePolicy["us-east-1"].ExampleRole1.a.data.PolicyDocument.Statement[0].Action = ["*"];
            let callback = (err, results) => {
                expect(results[0].status).to.equal(2);
                done();
            };

            iamRolePolicies.run(encodeCache(copied_cache), settings, callback)
        });

        it('should FAIL when action is literally *:*', function (done) {
            let settings = {};

            let copied_cache = JSON.parse(JSON.stringify(cache));
            copied_cache.iam.getRolePolicy["us-east-1"].ExampleRole1.a.data.PolicyDocument.Statement[0].Action = ["*:*"];
            let callback = (err, results) => {
                expect(results[0].status).to.equal(2);
                done();
            };

            iamRolePolicies.run(encodeCache(copied_cache), settings, callback)
        });

        it('should PASS when it is federated identity role, has wildcards, and ignore_identity_federation_roles is enabled', function (done) {
            let settings = {
                ignore_identity_federation_roles: 'true'
            };
            let copied_cache = JSON.parse(JSON.stringify(cache));
            copied_cache.iam.listRoles['us-east-1'].data[0].AssumeRolePolicyDocument.Statement[0].Action = 'sts:AssumeRoleWithSAML';
            copied_cache.iam.getRolePolicy["us-east-1"].ExampleRole1.a.data.PolicyDocument.Statement[0].Action = ["*:*"];
            copied_cache.iam.listRoles['us-east-1'].data[1].AssumeRolePolicyDocument.Statement[0].Action = 'sts:AssumeRoleWithWebIdentity';
            let callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            };

            iamRolePolicies.run(encodeCache(copied_cache), settings, callback)
        });

        it('should FAIL when it is federated identity role, has wildcards, and ignore_identity_federation_roles is disabled', function (done) {
            let settings = {
                ignore_identity_federation_roles: 'false'
            };
            let copied_cache = JSON.parse(JSON.stringify(cache));
            copied_cache.iam.listRoles['us-east-1'].data[0].AssumeRolePolicyDocument.Statement[0].Action = 'sts:AssumeRoleWithSAML';
            copied_cache.iam.getRolePolicy["us-east-1"].ExampleRole1.a.data.PolicyDocument.Statement[0].Action = ["*:*"];
            copied_cache.iam.listRoles['us-east-1'].data[1].AssumeRolePolicyDocument.Statement[0].Action = 'sts:AssumeRoleWithWebIdentity';
            let callback = (err, results) => {
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            };

            iamRolePolicies.run(encodeCache(copied_cache), settings, callback)
        });

        it('should FAIL when actions end with wildcard but ignore_service_specific_wildcards is disabled', function (done) {
            let settings = {
                ignore_service_specific_wildcards: 'false',
            };
            let callback = (err, results) => {
                expect(results[1].status).to.equal(2);
                done();
            };

            iamRolePolicies.run(encodeCache(cache), settings, callback)
        });
    });
});