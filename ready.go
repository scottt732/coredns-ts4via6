package tailscale

func (t *Tailscale) Ready() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.ready
}
