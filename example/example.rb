n = NetworkAnalyzer.new("enp0s3")
10.times do |i|
  sleep 3
  p n.current
end
