var qualities = [
    {pattern: /[0-9]/, value: 10}, // 0-9
    {pattern: /[a-z]/, value: 26}, // a-z
    {pattern: /[A-Z]/, value: 26}, // A-Z
    {pattern: /[\W]/, value: 32} // ,.<>+_!@#$%^&*()_+{}[]"|'\/?`~
];

var MIN_PASSWORD_LENGTH = 4;

var QUALITY = {
    min: 23,
    scale: 50,
};

function getBase(password) {
    var base = 0;
    for (var i = 0; i < qualities.length; ++i) {
        if (qualities[i].pattern.test(password)) {
            base += qualities[i].value;
        }
    }
    return base;
}

function getScore(password) {
    if (typeof password !== 'string') {
        return 0;
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
        0;
    }

    var base = Math.log(getBase(password));
    var len = password.length;

    var quality = len * base;

    var value = Math.max(0, Math.min((quality - QUALITY.min) / QUALITY.scale, 1));

    if (value <= 0) {
        return 0;
    }

    return value;
}
