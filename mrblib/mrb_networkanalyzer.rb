class NetworkAnalyzer
  def initialize(name)
    ::SignalThread.mask(:INT)
    self._new(name)
    pr = Proc.new do
      self._collect(name)
    end

    ::Thread.new(pr) do |local|
      local.call
    end
  end
end
