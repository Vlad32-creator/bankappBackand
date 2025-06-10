import express from 'express';
import {
    checkRegistration, changeName,
    checkTransfer, checkLogin,
    checkTokens, getCardNumber,
    getUsers,message,getMessage
} from './middleware.js';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import { PORT } from './config.js';

dotenv.config();


const app = express();
const bd = new Map();
const origin = ['https://vlad32-creator.github.io','http://localhost:5173'];

app.use(cors({
    origin: origin,
    credentials: true
}));
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.post('/registration', checkRegistration(bd));

app.post('/transfer', checkTransfer(bd), (req, res) => {
    res.send(`Transfer seccesse`);
});

app.get('/getUsers',getUsers(bd));

app.post('/login', checkLogin(bd));

app.post('/changeName', changeName(bd));

app.get('/ping',(req,res,next) => {
    res.send('pong');
});

app.post('/message',message(bd));
app.get('/getMessage',getMessage(bd));

app.get('/getCardNumber', getCardNumber(bd));

app.get('/checkTokens', checkTokens(bd));

app.listen(PORT, () => {
    console.log(`Server work on: ${PORT}`);
})

