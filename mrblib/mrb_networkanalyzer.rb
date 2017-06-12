class NetworkAnalyzer
  def initialize(name)
    self._new(name)
    pr = Proc.new do
      self._collect(name)
    end

    ::Thread.new(pr) do |local|
      local.call
    end
  end
end
