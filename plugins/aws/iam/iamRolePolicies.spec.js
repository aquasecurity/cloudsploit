var assert = require('assert');
var expect = require('chai').expect;
var iamRolePolicies = require('./iamRolePolicies');

// apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:listAttachedRolePolicies','IAM:getRolePolicy'],
const cache =  {
        iam: {
            listRoles: {
                "us-east-1": {
                    data: [
                        {
                          AssumeRolePolicyDocument: {
                            Version: "2012-10-17",
                            Statement: [
                              {
                                Action: "sts:AssumeRole",
                                Principal: {
                                  Service: "ec2.amazonaws.com"
                                },
                                Effect: "Allow",
                                Sid: ""
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
                                                "s3:*",
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
        it('should PASS when actions end with wildcard but only_look_at_action_star_effect_allow is enabled', function (done) {
            let settings = {
                only_look_at_action_star_effect_allow: 1,
            };

            let callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done();
            };

            iamRolePolicies.run(cache, settings, callback)
        });

        it('should FAIL when action is literally * and only_look_at_action_star_effect_allow is enabled', function (done) {
            let settings = {
                only_look_at_action_star_effect_allow: 1,
            };

            let copied_cache = JSON.parse(JSON.stringify(cache));
            copied_cache.iam.getRolePolicy["us-east-1"].ExampleRole1.a.data.PolicyDocument.Statement[0].Action = ["*"];
            let callback = (err, results) => {
                expect(results[0].status).to.equal(2);
                done();
            };

            iamRolePolicies.run(copied_cache, settings, callback)
        });

        it('should FAIL when actions end with wildcard but only_look_at_action_star_effect_allow is disabled', function (done) {
            let settings = {};
            let callback = (err, results) => {
                expect(results[1].status).to.equal(2);
                done();
            };

            iamRolePolicies.run(cache, settings, callback)
        });
    });
});