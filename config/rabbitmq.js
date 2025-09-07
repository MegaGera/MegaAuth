import amqp from 'amqplib';

let connection = null;
let channel = null;

const connectRabbitMQ = async () => {
  try {
    const rabbitmqUrl = process.env.MEGAQUEUE_URI;

    console.log('Connecting to RabbitMQ...');
    connection = await amqp.connect(rabbitmqUrl);
    channel = await connection.createChannel();

    // Declare the logging queue (Producer creates if needed)
    await channel.assertQueue('logging', {
      durable: true, // Messages will survive broker restarts
      exclusive: false, // Other connections can access it
      autoDelete: false // Queue persists when consumers disconnect
    });

    console.log('Connected to RabbitMQ successfully');

    // Handle connection events
    connection.on('error', (err) => {
      console.error('RabbitMQ connection error:', err.message);
    });

    connection.on('close', () => {
      console.log('RabbitMQ connection closed');
      connection = null;
      channel = null;
    });
  } catch (error) {
    console.error('Failed to connect to RabbitMQ:', error.message);
    // Don't exit the process, just log the error
    // The app should work without RabbitMQ if needed
  }
};

const getChannel = () => {
  return channel;
};

const isConnected = () => {
  return connection !== null && channel !== null;
};

export { connectRabbitMQ, getChannel, isConnected };
