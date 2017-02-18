math.randomseed(os.time())

request = function()
    local users = {}
    for i = 1, 3 do
        users[i] = 'users=' .. math.random(0, 100000) .. '%40gmail.com'
    end
    return wrk.format(nil, '/keys?' .. table.concat(users, '&'))
end
