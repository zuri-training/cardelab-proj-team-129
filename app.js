const express = require('express');
const userRouter = require('./routes/userRoutes')
const globalErrorHandler = require('./controller/errorController')
const morgan = require('morgan');
const app = express();

app.use(express.json());

// Development logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

// Routes
app.use('/api/v1/users', userRouter)

app.use(globalErrorHandler);
module.exports = app