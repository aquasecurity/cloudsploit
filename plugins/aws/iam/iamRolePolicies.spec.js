var assert = require('assert');
var expect = require('chai').expect;
var iamUserAdmins = require('./iamRolePolicies');

// apis needed in cache:
/* apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:listAttachedRolePolicies',
        'IAM:getPolicy', 'IAM:getRolePolicy'],
 */
const cache =  {  // TODO these aren't right, just copied over
        "iam": {
            "listRoles": {
                "us-east-1": {
                    "data": [
                        {
                        "RoleName": "test1@turner.com",
                        },
                        {
                        "RoleName": "test2@turner.com",
                        },
                    ]
                }
            },
            "listRolePolicies": {
                "us-east-1": {
                  "test1@turner.com": {
                    "data": {
                      "AttachedPolicies": [{"PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}],
                    }
                  },
                  "test2@turner.com": {
                    "data": {
                      "AttachedPolicies": [{"PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}],
                    }
                  },
                }
            },
            "listAttachedRolePolicies": {
                "us-east-1": {
                  "test1@turner.com": {
                    "data": {
                      "PolicyNames": [],
                    }
                  },
                  "test2@turner.com": {
                    "data": {
                      "PolicyNames": [],
                    }
                  },
                }
            },
            "getPolicy": {
                "us-east-1": {
                    "test1@turner.com": {
                        "data": {
                          "Groups": [],
                        }
                      },
                    "test2@turner.com": {
                        "data": {
                        "Groups": [],
                        }
                    },
                }
            },
            "getRolePolicy": {
                "us-east-1": {
                    "test1@turner.com": {
                        "data": {
                          "Groups": [],
                        }
                      },
                    "test2@turner.com": {
                        "data": {
                        "Groups": [],
                        }
                    },
                }
            }
        }
    }


describe('iamUserAdmins', function () {
    describe('run', function () {
        it('should FAIL when no users are found', function (done) {
            const settings = {
                iam_admin_count_minimum: 2,
                iam_admin_count_maximum: 2
            }

            const cache = [{}];


            const callback = (err, results) => {
                expect(results.length).to.equal(0)
                done()
            }

            iamUserAdmins.run(cache, settings, callback)
        })

        it('should FAIL when there are not enough users', function (done) {
            const settings = {
                iam_admin_count_minimum: 3,
                iam_admin_count_maximum: 3
            }

            const callback = (err, results) => {
                expect(results[0].status).to.equal(1)
                done()
            }

            iamUserAdmins.run(cache, settings, callback)
        })

        it('should FAIL when there are too many users', function (done) {
            const settings = {
                iam_admin_count_minimum: 0,
                iam_admin_count_maximum: 0
            }

            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                done()
            }

            iamUserAdmins.run(cache, settings, callback)
        })

        it('should PASS when users are found and fit within range', function (done) {
            const settings = {
                iam_admin_count_minimum: 1,
                iam_admin_count_maximum: 8
            }

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            }

            iamUserAdmins.run(cache, settings, callback)
        })
    })
})
