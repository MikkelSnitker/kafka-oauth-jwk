const {Kafka} = require("kafkajs");
const jwt = require("jsonwebtoken");
const kafka= new Kafka({
  clientId: 'my-app',
  brokers: ['localhost:9092'],
  // authenticationTimeout: 1000,
  // reauthenticationThreshold: 10000,
//  ssl: true,
  sasl: {
    mechanism: 'oauthbearer',
    oauthBearerProvider: async () => {
      // Use an unsecured token...
      const token = jwt.sign({ sub: 'test' }, 'abc', { algorithm: 'HS256' })
      // ...or, more realistically, grab the token from some OAuth endpoint
      return {
        value: "..." //token
      }
    }
  },
})



const consumer = kafka.consumer({ groupId: 'test-group' })
 
const run = async () => {


  // Consuming
  await consumer.connect()
  await consumer.subscribe({ topic: 'test-topic', fromBeginning: true })
 
  await consumer.run({
    eachMessage: async ({ topic, partition, message }) => {
      console.log({
        partition,
        offset: message.offset,
        value: message.value.toString(),
      })
    },
  })
}
 
run().catch(console.error)
