var expect = require('chai').expect;
const instanceLimit = require('./instanceLimit');

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
          {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-02e136e904f3da870",
            "InstanceId": "i-093b88477e4a07da3",
            "InstanceType": "t2.micro",
            "KeyName": "ec2-key",
            "LaunchTime": "2021-10-29T11:20:58.000Z",
            "Monitoring": {
              "State": "disabled"
            },
            "Placement": {
              "AvailabilityZone": "us-east-1b",
              "GroupName": "",
              "Tenancy": "default"
            },
            "PrivateDnsName": "ip-172-31-86-53.ec2.internal",
            "PrivateIpAddress": "172.31.86.53",
            "ProductCodes": [],
            "PublicDnsName": "ec2-3-82-108-10.compute-1.amazonaws.com",
            "PublicIpAddress": "3.82.108.10",
            "State": {
              "Code": 0,
              "Name": "pending"
            },
            "StateTransitionReason": "",
            "SubnetId": "subnet-673a9a46",
            "VpcId": "vpc-99de2fe4",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [
              {
                "DeviceName": "/dev/xvda",
                "Ebs": {
                  "AttachTime": "2021-10-29T11:20:59.000Z",
                  "DeleteOnTermination": true,
                  "Status": "attaching",
                  "VolumeId": "vol-00318657bf2aa47c9"
                }
              }
            ],
            "ClientToken": "",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "ElasticGpuAssociations": [],
            "ElasticInferenceAcceleratorAssociations": [],
            "NetworkInterfaces": [
              {
                "Association": {
                  "IpOwnerId": "amazon",
                  "PublicDnsName": "ec2-3-82-108-10.compute-1.amazonaws.com",
                  "PublicIp": "3.82.108.10"
                },
                "Attachment": {
                  "AttachTime": "2021-10-29T11:20:58.000Z",
                  "AttachmentId": "eni-attach-03337a722535833c9",
                  "DeleteOnTermination": true,
                  "DeviceIndex": 0,
                  "Status": "attaching",
                  "NetworkCardIndex": 0
                },
                "Description": "",
                "Groups": [
                  {
                    "GroupName": "launch-wizard-16",
                    "GroupId": "sg-09e13e2feaf15f550"
                  }
                ],
                "Ipv6Addresses": [],
                "MacAddress": "12:60:32:29:28:eb",
                "NetworkInterfaceId": "eni-0d2cce6aa20e13d34",
                "OwnerId": "000011112222",
                "PrivateDnsName": "ip-172-31-86-53.ec2.internal",
                "PrivateIpAddress": "172.31.86.53",
                "PrivateIpAddresses": [
                  {
                    "Association": {
                      "IpOwnerId": "amazon",
                      "PublicDnsName": "ec2-3-82-108-10.compute-1.amazonaws.com",
                      "PublicIp": "3.82.108.10"
                    },
                    "Primary": true,
                    "PrivateDnsName": "ip-172-31-86-53.ec2.internal",
                    "PrivateIpAddress": "172.31.86.53"
                  }
                ],
                "SourceDestCheck": true,
                "Status": "in-use",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "InterfaceType": "interface",
                "Ipv4Prefixes": [],
                "Ipv6Prefixes": []
              }
            ],
            "RootDeviceName": "/dev/xvda",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
              {
                "GroupName": "launch-wizard-16",
                "GroupId": "sg-09e13e2feaf15f550"
              }
            ],
            "SourceDestCheck": true,
            "Tags": [],
            "VirtualizationType": "hvm",
            "CpuOptions": {
              "CoreCount": 1,
              "ThreadsPerCore": 1
            },
            "CapacityReservationSpecification": {
              "CapacityReservationPreference": "open"
            },
            "HibernationOptions": {
              "Configured": false
            },
            "Licenses": [],
            "MetadataOptions": {
              "State": "pending",
              "HttpTokens": "optional",
              "HttpPutResponseHopLimit": 1,
              "HttpEndpoint": "enabled"
            },
            "EnclaveOptions": {
              "Enabled": false
            }
          }
        ],
        "OwnerId": "000011112222",
        "ReservationId": "r-0d80bb2f1b6a588aa"
    },
    {
        "Groups": [],
        "Instances": [
          {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-02e136e904f3da870",
            "InstanceId": "i-093b88477e4a07da3",
            "InstanceType": "t2.micro",
            "KeyName": "ec2-key",
            "LaunchTime": "2021-10-29T11:20:58.000Z",
            "Monitoring": {
              "State": "disabled"
            },
            "Placement": {
              "AvailabilityZone": "us-east-1b",
              "GroupName": "",
              "Tenancy": "default"
            },
            "PrivateDnsName": "ip-172-31-86-53.ec2.internal",
            "PrivateIpAddress": "172.31.86.53",
            "ProductCodes": [],
            "PublicDnsName": "ec2-3-82-108-10.compute-1.amazonaws.com",
            "PublicIpAddress": "3.82.108.10",
            "State": {
              "Code": 0,
              "Name": "running"
            },
            "StateTransitionReason": "",
            "SubnetId": "subnet-673a9a46",
            "VpcId": "vpc-99de2fe4",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [
              {
                "DeviceName": "/dev/xvda",
                "Ebs": {
                  "AttachTime": "2021-10-29T11:20:59.000Z",
                  "DeleteOnTermination": true,
                  "Status": "attaching",
                  "VolumeId": "vol-00318657bf2aa47c9"
                }
              }
            ],
            "ClientToken": "",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "ElasticGpuAssociations": [],
            "ElasticInferenceAcceleratorAssociations": [],
            "NetworkInterfaces": [
              {
                "Association": {
                  "IpOwnerId": "amazon",
                  "PublicDnsName": "ec2-3-82-108-10.compute-1.amazonaws.com",
                  "PublicIp": "3.82.108.10"
                },
                "Attachment": {
                  "AttachTime": "2021-10-29T11:20:58.000Z",
                  "AttachmentId": "eni-attach-03337a722535833c9",
                  "DeleteOnTermination": true,
                  "DeviceIndex": 0,
                  "Status": "attaching",
                  "NetworkCardIndex": 0
                },
                "Description": "",
                "Groups": [
                  {
                    "GroupName": "launch-wizard-16",
                    "GroupId": "sg-09e13e2feaf15f550"
                  }
                ],
                "Ipv6Addresses": [],
                "MacAddress": "12:60:32:29:28:eb",
                "NetworkInterfaceId": "eni-0d2cce6aa20e13d34",
                "OwnerId": "000011112222",
                "PrivateDnsName": "ip-172-31-86-53.ec2.internal",
                "PrivateIpAddress": "172.31.86.53",
                "PrivateIpAddresses": [
                  {
                    "Association": {
                      "IpOwnerId": "amazon",
                      "PublicDnsName": "ec2-3-82-108-10.compute-1.amazonaws.com",
                      "PublicIp": "3.82.108.10"
                    },
                    "Primary": true,
                    "PrivateDnsName": "ip-172-31-86-53.ec2.internal",
                    "PrivateIpAddress": "172.31.86.53"
                  }
                ],
                "SourceDestCheck": true,
                "Status": "in-use",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "InterfaceType": "interface",
                "Ipv4Prefixes": [],
                "Ipv6Prefixes": []
              }
            ],
            "RootDeviceName": "/dev/xvda",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
              {
                "GroupName": "launch-wizard-16",
                "GroupId": "sg-09e13e2feaf15f550"
              }
            ],
            "SourceDestCheck": true,
            "Tags": [],
            "VirtualizationType": "hvm",
            "CpuOptions": {
              "CoreCount": 10,
              "ThreadsPerCore": 10
            },
            "CapacityReservationSpecification": {
              "CapacityReservationPreference": "open"
            },
            "HibernationOptions": {
              "Configured": false
            },
            "Licenses": [],
            "MetadataOptions": {
              "State": "pending",
              "HttpTokens": "optional",
              "HttpPutResponseHopLimit": 1,
              "HttpEndpoint": "enabled"
            },
            "EnclaveOptions": {
              "Enabled": false
            }
          }
        ],
        "OwnerId": "000011112222",
        "ReservationId": "r-0d80bb2f1b6a588aa"
    }
];

const listServiceQuotas = [
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-85EED4F7",
      "QuotaCode": "L-85EED4F7",
      "QuotaName": "All DL Spot Instance Requests",
      "Value": 0,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "DL/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-88CF9481",
      "QuotaCode": "L-88CF9481",
      "QuotaName": "All F Spot Instance Requests",
      "Value": 64,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "F/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-3819A6DF",
      "QuotaCode": "L-3819A6DF",
      "QuotaName": "All G and VT Spot Instance Requests",
      "Value": 16,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "G/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-B5D1601B",
      "QuotaCode": "L-B5D1601B",
      "QuotaName": "All Inf Spot Instance Requests",
      "Value": 16,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "Inf/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-7212CCBC",
      "QuotaCode": "L-7212CCBC",
      "QuotaName": "All P Spot Instance Requests",
      "Value": 16,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "P/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-34B43A08",
      "QuotaCode": "L-34B43A08",
      "QuotaName": "All Standard (A, C, D, H, I, M, R, T, Z) Spot Instance Requests",
      "Value": 384,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "Standard/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-E3A00192",
      "QuotaCode": "L-E3A00192",
      "QuotaName": "All X Spot Instance Requests",
      "Value": 0,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "X/Spot",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-81657574",
      "QuotaCode": "L-81657574",
      "QuotaName": "Running Dedicated c5 Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-C93F66A2",
      "QuotaCode": "L-C93F66A2",
      "QuotaName": "Running Dedicated c5d Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-20F13EBD",
      "QuotaCode": "L-20F13EBD",
      "QuotaName": "Running Dedicated c5n Hosts",
      "Value": 1,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-8B27377A",
      "QuotaCode": "L-8B27377A",
      "QuotaName": "Running Dedicated d2 Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-CAE24619",
      "QuotaCode": "L-CAE24619",
      "QuotaName": "Running Dedicated g4dn Hosts",
      "Value": 1,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-8E60B0B1",
      "QuotaCode": "L-8E60B0B1",
      "QuotaName": "Running Dedicated i3 Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-77EE2B11",
      "QuotaCode": "L-77EE2B11",
      "QuotaName": "Running Dedicated i3en Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-5480EFD2",
      "QuotaCode": "L-5480EFD2",
      "QuotaName": "Running Dedicated inf Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-8B7BF662",
      "QuotaCode": "L-8B7BF662",
      "QuotaName": "Running Dedicated m5 Hosts",
      "Value": 1,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-8CCBD91B",
      "QuotaCode": "L-8CCBD91B",
      "QuotaName": "Running Dedicated m5d Hosts",
      "Value": 1,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-4FB7FF5D",
      "QuotaCode": "L-4FB7FF5D",
      "QuotaName": "Customer gateways per region",
      "Value": 50,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-0263D0A3",
      "QuotaCode": "L-0263D0A3",
      "QuotaName": "EC2-VPC Elastic IPs",
      "Value": 5,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-D0B7243C",
      "QuotaCode": "L-D0B7243C",
      "QuotaName": "New Reserved Instances per month",
      "Value": 20,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-D50A37FA",
      "QuotaCode": "L-D50A37FA",
      "QuotaName": "Running Dedicated m6g Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-EA4FD6CF",
      "QuotaCode": "L-EA4FD6CF",
      "QuotaName": "Running Dedicated r5 Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-8814B54F",
      "QuotaCode": "L-8814B54F",
      "QuotaName": "Running Dedicated r5d Hosts",
      "Value": 2,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-1586174D",
      "QuotaCode": "L-1586174D",
      "QuotaName": "Running Dedicated t3 Hosts",
      "Value": 1,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-6E869C2A",
      "QuotaCode": "L-6E869C2A",
      "QuotaName": "Running On-Demand DL instances",
      "Value": 0,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "DL/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-74FC7D96",
      "QuotaCode": "L-74FC7D96",
      "QuotaName": "Running On-Demand F instances",
      "Value": 64,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "F/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-DB2E81BA",
      "QuotaCode": "L-DB2E81BA",
      "QuotaName": "Running On-Demand G and VT instances",
      "Value": 16,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "G/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-43DA4232",
      "QuotaCode": "L-43DA4232",
      "QuotaName": "Running On-Demand High Memory instances",
      "Value": 0,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "HighMem/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-1945791B",
      "QuotaCode": "L-1945791B",
      "QuotaName": "Running On-Demand Inf instances",
      "Value": 16,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "Inf/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-417A185B",
      "QuotaCode": "L-417A185B",
      "QuotaName": "Running On-Demand P instances",
      "Value": 8,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "P/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-1216C47A",
      "QuotaCode": "L-1216C47A",
      "QuotaName": "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances",
      "Value": 384,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "Standard/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-7295265B",
      "QuotaCode": "L-7295265B",
      "QuotaName": "Running On-Demand X instances",
      "Value": 0,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false,
      "UsageMetric": {
        "MetricNamespace": "AWS/Usage",
        "MetricName": "ResourceCount",
        "MetricDimensions": {
          "Class": "X/OnDemand",
          "Resource": "vCPU",
          "Service": "EC2",
          "Type": "Resource"
        },
        "MetricStatisticRecommendation": "Maximum"
      }
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-B91E5754",
      "QuotaCode": "L-B91E5754",
      "QuotaName": "VPN connections per VGW",
      "Value": 10,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-3E6EC3A3",
      "QuotaCode": "L-3E6EC3A3",
      "QuotaName": "VPN connections per region",
      "Value": 50,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    },
    {
      "ServiceCode": "ec2",
      "ServiceName": "Amazon Elastic Compute Cloud (Amazon EC2)",
      "QuotaArn": "arn:aws:servicequotas:me-south-1:000011112222:ec2/L-7029FAB6",
      "QuotaCode": "L-7029FAB6",
      "QuotaName": "Virtual private gateways per region",
      "Value": 5,
      "Unit": "None",
      "Adjustable": true,
      "GlobalQuota": false
    }
];

const createCache = (quotas, instances) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
        },
        servicequotas: {
            listServiceQuotas: {
                'us-east-1': {
                    data: quotas
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            }
        },
        servicequotas: {
            listServiceQuotas: {
                'us-east-1': {
                    err: {
                        message: 'error listing quotas'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': null,
            },
        },
        servicequotas: {
            listServiceQuotas: {
                'us-east-1': null
            }
        }
    };
};


describe('instanceLimit', function () {
    describe('run', function () {
        it('should PASS if account contains instances less than the defined warn percentage', function (done) {
            const cache = createCache(listServiceQuotas, [describeInstances[0]]);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if account contains instances within the defined warn percentage', function (done) {
            const cache = createCache(listServiceQuotas, [describeInstances[1]]);
            instanceLimit.run(cache, { instance_limit_percentage_warn: '25' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if elastic ip usage is more than the defined fail percentage', function (done) {
            const cache = createCache(listServiceQuotas,[describeInstances[1]]);
            instanceLimit.run(cache, { instance_limit_percentage_fail: '20' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache(listServiceQuotas, []);
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to describe service quotas', function (done) {
            const cache = createErrorCache();
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list service quotas response not found', function (done) {
            const cache = createNullCache();
            instanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});