# mruby-network-analyzer   [![Build Status](https://travis-ci.org/pyama86/mruby-network-analyzer.svg?branch=master)](https://travis-ci.org/pyama86/mruby-network-analyzer)
NetworkAnalyzer class

code base is [iftop](http://www.ex-parrot.com/pdw/iftop/)

## install by mrbgems
- add conf.gem line to `build_config.rb`
- install `libpcap-dev`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :github => 'pyama86/mruby-network-analyzer'
end
```
## example
```ruby
# NetworkAnalyzer.collect(interface, collect_sec, collect_packet)
NetworkAnalyzer.collect("eth0", 3)
#=> [{"src_host"=>"10.0.2.15", "dst_host"=>"10.0.2.2", "src_port"=>":22", "dst_port"=>":58377", "total_sent"=>152, "total_recv"=>80, "sent_history"=>[152], "recv_history"=>[80]}]
```

## License
under the GPL License:
- see LICENSE file
