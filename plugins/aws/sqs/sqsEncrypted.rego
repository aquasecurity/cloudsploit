package sqs.encryption

default allow = false

allow = true {
    count(violation) == 0
}

violation[name] {
    some i
    name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
	region := location
	not input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
}

# encryption disabled
sqsencdis[region]  =  sqsNames {
    name := input.sqs.getQueueAttributes[location][_].data.Attributes.QueueArn
	region := location
	input.sqs.getQueueAttributes[location][_].data.Attributes
    sqsNames := [name |
					name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
					not input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
					]
}


# encryption enabled with default key
sqsencdefault[region]  =  sqsNames {
    name := input.sqs.getQueueAttributes[location][_].data.Attributes.QueueArn
	region := location
	input.sqs.getQueueAttributes[location][_].data.Attributes
    sqsNames := [name |
					name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
					input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
					input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId == "alias/aws/sqs"
					]
}


# encryption enabled with CMK key
sqsenccmk[region]  =  sqsNames {
    name := input.sqs.getQueueAttributes[location][_].data.Attributes.QueueArn
	region := location
	input.sqs.getQueueAttributes[location][_].data.Attributes
    sqsNames := [name |
					name := input.sqs.getQueueAttributes[location][i].data.Attributes.QueueArn
					input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId
					input.sqs.getQueueAttributes[location][i].data.Attributes.KmsMasterKeyId != "alias/aws/sqs"
					]
}