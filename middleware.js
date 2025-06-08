import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import {
    JWT_ACCESS_SECRET,
    JWT_ACCESS_EXPIRATION,
    JWT_REFRESH_SECRET,
    JWT_REFRESH_EXPIRATION
} from './config.js';
const secure = true;
const sameSite = 'none';

function toDoCardNumber() {
    let cardNumber = '';
    for (let i = 0; i < 12; i++) {
        const random = Math.floor(Math.random() * 10);
        cardNumber += random;
    }
    return cardNumber;
}

function checkCardNumber(bd) {
    let userCard;
    do {
        userCard = toDoCardNumber();
    } while (bd.has(userCard));
    return userCard;
}

function checkUserName(bd, name) {
    for (let [key, value] of bd) {
        if (value.name === name) {
            return true;
        }
    }
    return false;
}

function generationTokens(user) {
    const accessToken = jwt.sign({ id: user.id, name: user.name }, JWT_ACCESS_SECRET, { expiresIn: JWT_ACCESS_EXPIRATION });
    const refreshToken = jwt.sign({ id: user.id, name: user.name }, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRATION });
    return { accessToken, refreshToken };
}

function verifyTokens(req, res, next) {
    const { accessToken, refreshToken } = req.cookies;

    if (!accessToken || !refreshToken) {
        return res.status(401).json({ error: `Tokens not found` });
    }
    jwt.verify(accessToken, JWT_ACCESS_SECRET, (error, decodedAccessToken) => {
        if (error) {
            jwt.verify(refreshToken, JWT_REFRESH_SECRET, (error, decodedRefreshToken) => {
                if (error) {

                    return res.status(401).send({ Error: `Invalid Tokens` });
                } else {
                    const newAccessToken = jwt.sign(
                        {
                            id: decodedRefreshToken.id,
                            name: decodedRefreshToken.name
                        },
                        JWT_ACCESS_SECRET, {
                        expiresIn: '15m'
                    })
                    res.cookie('accessToken', newAccessToken, {
                        httpOnly: true,
                        secure: secure,
                        sameSite: sameSite,
                        maxAge: 15 * 60 * 1000
                    });
                    req.user = decodedRefreshToken;
                    return next();
                }
            })
        } else {
            req.user = decodedAccessToken;
            return next();
        }
    })
}

function makeColor() {
    const random = Math.floor(Math.random() * 360);
    const color = `hsl(${random},100%,50%)`;
    return color;
}

export function checkRegistration(bd) {
    return async function (req, res, next) {
        const userCard = checkCardNumber(bd);
        const { name, password } = req.body;
        const errors = {}
        if (!name) {
            errors.name = `Fill field name`;
        } if (!password) {
            errors.password = `Fill field password`;
        } if (password.length < 6) {
            errors.password = `Password must be 6 or more`;
        } if (checkUserName(bd, name)) {
            errors.name = `Name taken`;
        } if ((/[^a-zA-Zа-яА-ЯёЁ0-9]/g).test(name)) {
            errors.name = 'Unacceptable characters';
        } if ((/[^a-zA-Zа-яА-ЯёЁ0-9]/g).test(password)) {
            errors.password = 'Unacceptable characters';
        } if (name === '') {
            errors.name = `Fill out the forms`;
        } if (password.trim() === '') {
            errors.password = `Fill out the forms`;
        } if (Object.keys(errors).length > 0) {
            return res.send({ Error: errors });
        }
        if (bd.size > 11) {
            const firstKey = bd.keys().next().value;
            bd.delete(firstKey);
        }
        const [hashName, hashPassword] = await Promise.all([
            bcrypt.hash(name.trim(), 10),
            bcrypt.hash(password.trim(), 10),
        ]);
        const id = Date.now() + Math.random();
        const user = { id: id, name: name };
        const userColor = makeColor();
        const { accessToken, refreshToken } = generationTokens(user);
        bd.set(userCard,
            {
                id: id,
                name: name,
                hashName: hashName,
                hashPassword: hashPassword,
                cardNumber: userCard,
                money: 2000,
                refreshToken: refreshToken,
                userColor: userColor,
                message: []
            });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: secure,
            sameSite: sameSite,
            maxAge: 7 * 24 * 60 * 60 * 1000
        }).cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: secure,
            sameSite: sameSite,
            maxAge: 15 * 60 * 1000
        }).json({ name: name, cardNumber: userCard.slice(8), userColor: userColor, balance: 2000 });
        return;
    }
}


export function changeName(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) {
                return res.send({ Error: `Invalid Token` });
            }
            const { newName } = req.body;
            if (newName === req.user.name) {
                return res.status(401).send({ Error: `Change name please` });
            } if (!newName || newName.trim() === '') {
                return res.status(401).send({ Error: `Cannot be empty` });
            } if ((/[^a-zA-Zа-яА-ЯёЁ0-9]/g).test(newName)) {
                return res.status(401).send({ Error: `Unacceptable characters` });
            }
            for (let [key, value] of bd) {
                value.name = newName;
                const user = { id: req.user.id, name: newName }
                const { accessToken, refreshToken } = generationTokens(user);
                return res.cookie("accessToken", accessToken, {
                    httpOnly: true,
                    secure: secure,
                    sameSite: sameSite,
                    maxAge: 15 * 60 * 1000
                }).cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: secure,
                    sameSite: sameSite,
                    maxAge: 7 * 24 * 60 * 60 * 1000
                }).json({ newName: newName });
            }
        });
    }
}

export function checkTransfer(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) {
                return;
            }
            const { money, recipientCard } = req.body;
            const userEntry = [...bd.entries()].find(([_, user]) => user.name === req.user.name);
            const errors = {};
            if (!recipientCard) {
                return res.status(401).json({ Error: `Enter recipient card` });
            } if (!money) {
                return res.status(401).json({ Error: `Enter how mach money do you wont to transfer` });
            } if (money && recipientCard) {
                if (!bd.has(recipientCard)) {
                    errors.card = `Cannot find recipient Card`;
                    return res.status(400).json({ errors });
                } if (money < 0) {
                    errors.money = 'Transaction amount must be greater than 0';
                    return res.status(400).json({ errors });
                }
                userEntry[1].money = userEntry[1].money - money;
                bd.get(recipientCard).money += money;
                return res.json({ success: true, newBalance: userEntry[1].money });
            }
        })
    }
}

export function checkLogin(bd) {
    return async function (req, res, next) {
        const { name, password } = req.body;
        if (!name) {
            return res.send({ Error: { name: `Enter data` } }); ``
        } if (!password) {
            return res.send({ Error: { password: 'Enter data' } });
        }
        const userEntry = [...bd.entries()].find(([_, user]) => user.name === name);
        if (!userEntry) {
            return res.send({ Error: { name: `User not found` } });
        }
        const isPasswordValid = await bcrypt.compare(password, userEntry[1].hashPassword);
        if (!isPasswordValid) {
            return res.send({ Error: { password: `Password is not valid` } });
        }
        const user = { id: userEntry[1].id, name: userEntry[1].name };
        const { accessToken, refreshToken } = generationTokens(user);
        userEntry[1].refreshToken = refreshToken;
        return res.status(200).cookie(
            'accessToken', accessToken, {
            httpOnly: true,
            secure: secure,
            sameSite: sameSite,
            maxAge: 15 * 60 * 1000
        }
        ).cookie(
            "refreshToken", refreshToken, {
            httpOnly: true,
            secure: secure,
            sameSite: sameSite,
            maxAge: 7 * 24 * 60 * 60 * 1000
        }
        ).json({ name: name, cardNumber: userEntry[1].cardNumber.slice(8), balance: userEntry[1].money, userColor: userEntry[1].userColor });
    }
}

export function checkTokens(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) {
                return res.status(401).json({ error: error.message });
            }

            const userEntry = [...bd.entries()].find(
                ([_, user]) => user.name === req.user.name && user.id === req.user.id
            );

            if (!userEntry) {
                return res.status(404).json({ error: 'User not found' });
            }

            return res.json({ success: true, name: userEntry[1].name, balance: userEntry[1].money, cardNumber: userEntry[1].cardNumber.slice(8) });
        });
    }
}


export function getCardNumber(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) {
                return;
            }
            const userEntry = [...bd.entries()].find(([_, user]) =>
                user.id === req.user.id && user.name === req.user.name);
            return res.status(200).json({ cardNumber: userEntry[1].cardNumber });
        })
    }
}

export function getUsers(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) return;
            const users = [...bd.values()].map(user => {
                return {
                    userName: user.name,
                    userColor: user.userColor
                }
            })
            return res.json(users);
        })
    }
}

export function message(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) return;
            const message = req.body;
            const sender = req.user.name;
            if (!message.card) {
                return res.json({ Error: 'None card' });
            }

            const recipient = [...bd.values()].find(user => user.name === message.recipient);
            if (recipient.message.length >= 5) {
                recipient.message.shift();
            }

            recipient.message.push({ text: message.text, card: message.card, sender: sender });
            return res.json({ success: true });
        })
    }
}

export function getMessage(bd) {
    return function (req, res, next) {
        verifyTokens(req, res, (error) => {
            if (error) return;
            const my = [...bd.values()].find(user => user.name === req.user.name);
            return res.json(my.message);
        })
    }
}