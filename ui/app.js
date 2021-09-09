Array.prototype.last = function () {
  return this[this.length - 1];
}

Number.prototype.fileSize = function (a, b, c, d) {
  return (a = a ? [1e3, 'k', 'B'] : [1024, 'K', 'iB'], b = Math, c = b.log,
    d = c(this) / c(a[0]) | 0, this / b.pow(a[0], d)).toFixed(2)
    + ' ' + (d ? (a[1] + 'MGTPEZY')[--d] + a[2] : 'Bytes');
};

const API_PREFIX = "/api";
const app = Vue.createApp({
  data() {
    return {
      currentTab: 'live',
      tabs: [{ title: 'Live', slug: 'live' }, { title: 'History', slug: 'history' }, { title: 'Rules', slug: 'rules' }],
      autoRefresh: false,
    }
  },
  computed: {
    currentTabComponent() {
      return 'tab-' + this.currentTab
    }
  },
  mounted() {
    if (localStorage.autoRefresh) {
      this.autoRefresh = localStorage.autoRefresh == "true";
    }

    window.addEventListener("popstate", () => this.setupTab());
    this.setupTab();
    this.setupTimeout()
  },
  unmounted() {
    clearTimeout(this.timeout);
  },
  watch: {
    autoRefresh(val) {
      localStorage.autoRefresh = val;
    },
    currentTab(val) {
      history.replaceState(val, "", '#' + val);
    }
  },
  methods: {
    setupTab() {
      if (location.hash) {
        let hash = location.hash.substr(1);
        let t = this.tabs.find((tab) => tab.slug == hash);
        console.log(hash, t);
        if (t) {
          this.currentTab = t.slug;
        }
      }
    },
    setupTimeout() {
      this.timeout = setTimeout(() => {
        this.loadData()
      }, 5000)
    },
    loadData() {
      if (this.autoRefresh) {
        try {
          this.$refs.current.loadData()
        } catch (err) {
          console.error(err);
        }
      }
      this.setupTimeout()
    }
  }
})

app.component('tab-live', {
  template: `
    <div class="live-tab">
      <contexts :list=list></contexts>
    </div>`,
  data() {
    return {
      list: []
    }
  },
  mounted() { this.loadData(); },
  methods: {
    async loadData() {
      let response = await fetch(API_PREFIX + '/live');
      if (response.status !== 200) {
        console.log('Response Error', response);
        return;
      }
      let data = await response.json();
      // console.info(data);
      data.sort((a, b) => a.id - b.id);
      this.list = data;
    }
  }
})

app.component('tab-history', {
  template: `
  <div class="history-tab">
    <contexts :list=list></contexts>
  </div>`,
  data() {
    return {
      list: []
    }
  },
  mounted() { this.loadData(); },
  methods: {
    async loadData() {
      let response = await fetch(API_PREFIX + '/history')
      if (response.status !== 200) {
        console.log('Response Error', response);
        return;
      }
      let data = await response.json()
      // console.info(data);
      this.list = data;
    }
  }
})

app.component('tab-rules', {
  template: `
  <div class="rules-tab">
    <ol class="list-group list-group-numbered">
      <li v-for="item in list" class="list-group-item d-flex justify-content-between align-items-start">
        <dl class="row ms-2 me-auto">
          <dt v-if=item.filter>filter</dt>
          <dd v-if=item.filter>{{item.filter}}</dd>
          <dt>target</dt>
          <dd>{{item.target}}</dd>
        </dl>
        <rule-stats :stats=item.stats></rule-stats>
      </li>
    </ol>
  </div>`,
  data() {
    return {
      list: []
    }
  },
  mounted() { this.loadData(); },
  methods: {
    async loadData() {
      let response = await fetch(API_PREFIX + '/rules')
      if (response.status !== 200) {
        console.log('Response Error', response);
        return;
      }
      let data = await response.json()
      // console.info(data);
      this.list = data;
    }
  }
})

app.component('rule-stats', {
  props: { stats: Object },
  template: `
  <span class="badge bg-primary rounded-pill">E:{{stats.exec}}</span>&nbsp;
  <span class="badge bg-success rounded-pill">H:{{stats.hits}}</span>&nbsp;
  <span class="badge bg-secondary rounded-pill">T:{{time}}ns</span>
  `,
  computed: {
    time() {
      if (this.stats.exec) {
        this.stats.time / this.stats.exec
      } else {
        return 0;
      }
    }
  }
})
app.component('contexts', {
  props: { list: Array },
  template: `
  <table id="context-list" class="table table-striped table-hover">
  <thead>
    <tr>
      <th scope="col">#</th>
      <th scope="col">Source</th>
      <th scope="col">Target</th>
      <th scope="col">Listener</th>
      <th scope="col">Connector</th>
      <th scope="col">State</th>
      <th scope="col" colspan="2">Stats</th>
  </thead>
  <tbody>
    <context-row v-for="item in list" :item=item></context-row>
  </tbody>
  </table>`
})

app.component('context-row', {
  props: { item: Object },
  template: `
<tr scope="row">
  <td>{{ item.id }}</td>
  <td>{{ item.source }}</td>
  <td>{{ item.target }}</td>
  <td>{{ item.listener }}</td>
  <td>{{ item.connector }}</td>
  <td><context-state :item=item></context-state></td>
  <td>&#9650; {{ item.client_stat.read_bytes.fileSize() }}</td>
  <td>&#9660; {{ item.server_stat.read_bytes.fileSize() }}</td>
</tr>
`
})

app.component('context-state', {
  props: { item: Object },
  template: `
  <span class="my_tooltip">
    {{ state }}
    <span class="my_tooltiptext">
      <span>{{ time }}</span><br/>
      <span v-if=error>{{ error }}</span>
    </span>
  </span>`,
  computed: {
    state() {
      return this.item.state.last().state;
    },
    time() {
      return new Date(this.item.state.last().time).toLocaleString();
    },
    error() {
      return this.item.error ? `Error: ${this.item.error}` : "";
    }
  }
})


window.onload = function () {
  console.info("onload");
  app.mount('#root-component');
}