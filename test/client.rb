require 'rubygems'
require 'ffi-rzmq'

# if ARGV.length < 3
#   puts "usage: ruby remote_lat.rb <connect-to> <message-size> <roundtrip-count>"
#   exit
# end

def assert(rc)
  # puts "rc: #{rc}"
  raise "Last API call failed at #{caller(1)}" unless rc >= 0
end

i = 0
connect_to = ARGV[0] || "tcp://localhost:5555"
message_size = (ARGV[1] || 10).to_i
roundtrip_count = (ARGV[2] || 10).to_i

ctx = ZMQ::Context.new

loop do
  s   = ctx.socket ZMQ::DEALER
  # set heartbeat interval
  lookup = s.instance_variable_get(:@option_lookup)
  lookup[ZMQ::HEARTBEAT_IVL] = 0
  rc  = s.setsockopt(ZMQ::HEARTBEAT_IVL, 2000, 4)

  assert(rc)
  assert(s.connect(connect_to))


  10.times do
    i+=1
    msg = "#{ (i.to_s + " ") * message_size }"
    puts "sending #{i}"
    # puts "sending #{msg}"
    assert(s.send_string("header", ZMQ::SNDMORE))
    assert(s.send_string(msg, ZMQ::SNDMORE))
    assert(s.send_string("footer", 0))

    #msg = ''
    #assert(s.recv_string(msg, 0))

    #raise "Message size doesn't match, expected [#{message_size}] but received [#{msg.size}]" if message_size != msg.size
    sleep rand(0.5..1)

  end

  s.close()
  sleep rand(0.5..1)
end


# for i in {1..100} ; do; ( ruby client.rb & ) ; done
