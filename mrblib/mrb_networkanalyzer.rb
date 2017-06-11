class NetworkAnalyzer
  def initialize(name)
    pr = Proc.new do
      self._collect(name)
    end

    ::Thread.new(pr) do |local|
      local.call
    end
  end
end
