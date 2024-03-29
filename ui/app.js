Array.prototype.last = function () {
  return this[this.length - 1];
}

Number.prototype.fileSize = function (a, b, c, d) {
  return (a = a ? [1e3, 'k', 'B'] : [1024, 'K', 'iB'], b = Math, c = b.log,
    d = c(this) / c(a[0]) | 0, this / b.pow(a[0], d)).toFixed(2)
    + ' ' + (d ? (a[1] + 'MGTPEZY')[--d] + a[2] : 'Bytes');
};

Number.prototype.timeSince = function () {
  return new Date(this).timeSince()
}

Date.prototype.timeSince = function () {
  var ret = "";
  var seconds = Math.floor((new Date() - this) / 1000);
  var interval = Math.floor(seconds / 86400);
  if (interval > 1) {
    ret += interval + " days ";
    seconds -= interval * 86400;
  }
  interval = Math.floor(seconds / 3600);
  if (interval > 1) {
    ret += interval + " hours ";
    seconds -= interval * 3600;
  }
  interval = Math.floor(seconds / 60);
  if (interval > 1) {
    ret += interval + " minutes ";
    seconds -= interval * 60;
  }
  return ret + Math.floor(seconds) + " seconds ago";
}

const API_PREFIX = "/api";
const TITLE_SURFIX = ' - redproxy-rs console';
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
      let t = this.tabs.find((tab) => tab.slug == val);
      document.title = t.title + TITLE_SURFIX;
      history.replaceState(val, "", '#' + val);
    }
  },
  methods: {
    setupTab() {
      if (location.hash) {
        let hash = location.hash.substr(1);
        let t = this.tabs.find((tab) => tab.slug == hash);
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
  template: "#tab-rules",
  data() {
    return {
      list: [],
      editing: false
    }
  },
  methods: {
    async loadData() {
      if (this.editing) return;
      let response = await fetch(API_PREFIX + '/rules')
      if (response.status !== 200) {
        console.log('Response Error', response);
        return;
      }
      let data = await response.json()
      this.list = data;
    },
    startEditing() {
      // switch to editing mode
      this.editing = true;
    },
    finishEditing() {
      // switch back to non-editing mode
      this.editing = false;
    }
  },
  mounted() {
    this.loadData();
  }
})

app.component('edit-rules', {
  template: "#tab-rules-edit",
  props: ['rules'],
  watch: {
    rules: {
      handler: function (newValue, oldValue) {
        this.rules.forEach((rule) => {
          if (rule.filter === '') {
            rule.filter = null;
          }
        });
      },
      deep: true,
    },
  },
  methods: {
    addRule() {
      // add a new rule to the rules array
      this.rules.push({
        filter: '',
        target: 'deny',
      });
    },
    deleteRule(index) {
      // delete the rule at the specified index
      this.rules.splice(index, 1);
    },
    async commitChanges() {
      // commit changes to the rules on the API server
      let response = await fetch(API_PREFIX + '/rules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(this.rules)
      });
      if (response.status !== 200) {
        console.log('Error committing changes', response);
      } else {
        // emit done event to indicate that the changes have been committed
        this.$emit('done');
      }
    },
    moveUp(index) {
      // move the rule at the specified index up one position
      let rule = this.rules[index];
      this.rules.splice(index, 1);
      this.rules.splice(index - 1, 0, rule);
    },
    moveDown(index) {
      // move the rule at the specified index down one position
      let rule = this.rules[index];
      this.rules.splice(index, 1);
      this.rules.splice(index + 1, 0, rule);
    }
  },
  data() {
    return {
      //rules: [],
      targets: [],
    }
  },
  mounted() {
    fetch(API_PREFIX + '/status')
      .then((response) => response.json())
      .then((data) => {
        let list = data.connectors;
        list.push("deny");
        this.targets = list;
      });
  },
});

app.component('rule-stats', {
  props: { stats: Object },
  template: `
  <span class="badge bg-primary rounded-pill">E:{{stats.exec}}</span>&nbsp;
  <span class="badge bg-success rounded-pill">H:{{stats.hits}}</span>&nbsp;
  <span class="badge bg-secondary rounded-pill">T:{{time}}us</span>
  `,
  computed: {
    time() {
      if (this.stats.exec) {
        return (this.stats.time / this.stats.exec / 1000).toFixed(2);
      } else {
        return 0;
      }
    }
  }
})
app.component('contexts', {
  props: { list: Array },
  template: "#context-list"
})

app.component('context-row', {
  props: { item: Object },
  template: "#context-row"
})

app.component('tooltip', {
  template: "#tooltip",
});

app.component('context-state', {
  props: { item: Object },
  template: "#context-state",
  computed: {
    state() {
      return this.item.state.last().state;
    },
    error() {
      return this.item.error || "";
    }
  }
})

window.onload = function () {
  console.info("onload");
  app.mount('#root-component');
}