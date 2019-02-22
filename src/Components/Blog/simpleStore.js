class SimpleStore {
	constructor() {
		this.state = {}
	}

	set(k, v) {
		this.state[k] = v
	}

	get(k) {
		return this.state[k]
	}
}

export default new SimpleStore()