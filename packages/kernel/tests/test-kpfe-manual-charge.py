#!/usr/bin/env python3
"""Exercise actual diagnostic C functions with a simulated GLINK transport."""
from pathlib import Path
import subprocess
import sys
import tempfile
import atexit

temporary = tempfile.TemporaryDirectory(prefix='kpfe-manual-charge-test-')
atexit.register(temporary.cleanup)
root = Path(temporary.name)
if len(sys.argv) != 2:
    raise SystemExit('usage: test-kpfe-manual-charge.py PATH_TO_PATCHED_QCOM_BATTMGR_C')
source = Path(sys.argv[1]).read_text()

def function(name):
    import re
    match = re.search(r'^static [^\n]+\b' + name + r'\(', source, re.M)
    if not match:
        raise ValueError(name)
    start = match.start()
    opening = source.index('{', match.end())
    level = 1
    end = opening + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint32_t __le32;
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define HZ 100
#define PMIC_GLINK_OWNER_BATTMGR 0x800a
#define PMIC_GLINK_REQ_RESP 1
#define BATTMGR_SET_CHARGE_RATE 0x06
#define BATTMGR_NOTIFICATION 0x07
#define BATTMGR_BAT_PROPERTY_GET 0x30
#define BATTMGR_BAT_PROPERTY_SET 0x31
#define BATTMGR_CHG_CTRL_LIMIT_EN 0x48
#define BATT_CHG_CTRL_EN 24
#define BATT_CHG_CTRL_LIM 10
#define CHARGE_CTRL_END_THR_MAX 100
#define POWER_SUPPLY_CHARGE_BEHAVIOUR_AUTO 0
#define POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE 1
#define QCOM_BATTMGR_SC8280XP 1
#define QCOM_BATTMGR_X1E80100 3
#define SERVREG_SERVICE_STATE_UP 1
struct pmic_glink_hdr { __le32 owner, type, opcode; };
struct qcom_battmgr_charge_rate_request { struct pmic_glink_hdr hdr; __le32 battery_id, charge_rate, charging_path; };
struct qcom_battmgr_charge_ctrl_request { struct pmic_glink_hdr hdr; __le32 enable, target_soc, delta_soc; };
struct qcom_battmgr_property_request { struct pmic_glink_hdr hdr; __le32 battery, property, value; };
union power_supply_propval { int intval; };
struct qcom_battmgr {
    void *client, *bat_psy;
    int error, ack, lock, variant, enable_work;
    bool service_up, charge_rate_supported, charge_rate_inhibited, charge_rate_known, native_charge_limit_enabled, native_charge_limit_valid;
    u32 service_epoch, charge_rate_epoch, pending_opcode;
    struct { int charge_current_limit; } info;
};
static struct qcom_battmgr *active;
static int sends, rate_sends, rate, request_enable, fault, restarts, rejected_wrong_ack;
static bool native_enabled;
static void mutex_lock(int *m) { assert(!*m); *m = 1; }
static void mutex_unlock(int *m) { assert(*m); *m = 0; }
static void reinit_completion(int *p) { *p = 0; }
static void complete(int *p) { *p = 1; }
static unsigned long wait_for_completion_timeout(int *p, int timeout) { return *p; }
static void power_supply_changed(void *p) {}
static void schedule_work(int *p) { ++*p; }
static void qcom_battmgr_notification(struct qcom_battmgr *b, const void *data, size_t len) {}
static void qcom_battmgr_sm8350_callback(struct qcom_battmgr *b, const void *data, size_t len) {
    const struct pmic_glink_hdr *h = data;
    if (h->opcode == BATTMGR_BAT_PROPERTY_GET) {
        b->native_charge_limit_enabled = native_enabled;
        b->native_charge_limit_valid = fault != 6;
        if (restarts) { ++b->service_epoch; restarts = 0; }
    }
    complete(&b->ack);
}
static void qcom_battmgr_sc8280xp_callback(struct qcom_battmgr *b, const void *data, size_t len) { assert(0); }
static void qcom_battmgr_callback(const void *, size_t, void *);
static int pmic_glink_send(void *client, const void *data, size_t len) {
    const struct pmic_glink_hdr *h = data;
    struct { struct pmic_glink_hdr hdr; u32 result; } ack = { .hdr = *h };
    assert(active->lock);
    ++sends;
    if (h->opcode == BATTMGR_CHG_CTRL_LIMIT_EN) request_enable = ((const struct qcom_battmgr_charge_ctrl_request *)data)->enable;
    if (h->opcode == BATTMGR_SET_CHARGE_RATE) {
        const struct qcom_battmgr_charge_rate_request *r = data;
        assert(len == 24 && r->battery_id == 0 && r->charging_path == 0);
        assert(h->owner == 0x800a && h->type == 1);
        ++rate_sends; rate = r->charge_rate;
        if (fault == 1) return 0;
        if (fault == 2) { qcom_battmgr_callback(&ack, 12, active); return 0; }
        if (fault == 3) ack.result = 7;
        if (fault == 4) {
            ack.hdr.opcode = BATTMGR_BAT_PROPERTY_GET;
            qcom_battmgr_callback(&ack, sizeof(ack), active);
            assert(!active->ack); rejected_wrong_ack++;
            ack.hdr = *h;
        }
        if (fault == 5) ++active->service_epoch;
    }
    qcom_battmgr_callback(&ack, sizeof(ack), active);
    return 0;
}
'''
names = ['qcom_battmgr_request', 'qcom_battmgr_request_property',
         'qcom_battmgr_get_charge_rate_behaviour', 'qcom_battmgr_set_charge_control',
         'qcom_battmgr_set_charge_current_limit', 'qcom_battmgr_set_charge_rate_behaviour',
         'qcom_battmgr_charge_rate_ack', 'qcom_battmgr_callback', 'qcom_battmgr_pdr_notify']
tests = r'''
static struct qcom_battmgr fresh(void) {
    sends = rate_sends = fault = restarts = rejected_wrong_ack = 0;
    native_enabled = false;
    return (struct qcom_battmgr){.charge_rate_supported=true, .service_up=true, .service_epoch=1};
}
int main(void) {
    struct qcom_battmgr b = fresh(); active = &b;
    union power_supply_propval v;
    assert(qcom_battmgr_get_charge_rate_behaviour(&b, &v) == -ENODATA);
    native_enabled=true;
    assert(qcom_battmgr_set_charge_rate_behaviour(&b, 1) == -EBUSY && !rate_sends);
    native_enabled=false;
    assert(!qcom_battmgr_set_charge_rate_behaviour(&b, 1) && rate==0 && rate_sends==1);
    assert(!qcom_battmgr_get_charge_rate_behaviour(&b, &v) && v.intval==1);
    assert(!qcom_battmgr_set_charge_rate_behaviour(&b, 0) && rate==100 && rate_sends==2);
    assert(!qcom_battmgr_get_charge_rate_behaviour(&b, &v) && v.intval==0);
    int count=sends;
    assert(qcom_battmgr_set_charge_control(&b, 80, 5)==-EBUSY && sends==count);
    assert(qcom_battmgr_set_charge_current_limit(&b, 0)==-EBUSY && sends==count);
    mutex_lock(&b.lock);
    assert(!qcom_battmgr_set_charge_control(&b, 100, 5) && request_enable==0);
    mutex_unlock(&b.lock);
    count=sends;
    assert(qcom_battmgr_set_charge_rate_behaviour(&b, 2)==-EINVAL && sends==count);
    b.charge_rate_supported=false;
    assert(qcom_battmgr_set_charge_rate_behaviour(&b, 1)==-EOPNOTSUPP && sends==count);
    b=fresh();
    const int errors[]={0,-ETIMEDOUT,-ENODATA,-EIO,0,-EAGAIN};
    for (int f=1; f<=5; ++f) {
        b=fresh();
        assert(!qcom_battmgr_set_charge_rate_behaviour(&b, 0));
        fault=f;
        assert(qcom_battmgr_set_charge_rate_behaviour(&b, 1)==errors[f]);
        if(f==4) assert(rejected_wrong_ack==1 && b.charge_rate_known);
        else assert(qcom_battmgr_get_charge_rate_behaviour(&b, &v)==-ENODATA);
    }
    b=fresh(); restarts=1;
    assert(qcom_battmgr_set_charge_rate_behaviour(&b, 1)==-EAGAIN && !rate_sends);
    b=fresh(); fault=6;
    assert(qcom_battmgr_set_charge_rate_behaviour(&b, 1)==-EPROTO && !rate_sends);
    b=fresh(); assert(!qcom_battmgr_set_charge_rate_behaviour(&b, 1));
    count=sends;
    qcom_battmgr_pdr_notify(&b, 0);
    qcom_battmgr_pdr_notify(&b, SERVREG_SERVICE_STATE_UP);
    assert(qcom_battmgr_get_charge_rate_behaviour(&b, &v)==-ENODATA && sends==count);
    assert(b.enable_work==1);
    struct pmic_glink_hdr short_header={0};
    qcom_battmgr_callback(&short_header, 1, &b);
    b=fresh(); b.service_up=false;
    assert(qcom_battmgr_set_charge_rate_behaviour(&b, 1)==-EAGAIN && !sends);
    puts("PASS: manual rate payloads, policy exclusion, unknown state, response validation, timeout and service restart cases");
}
'''
path = root / 'manual-charge-harness.c'
path.write_text(prefix + '\n\n'.join(function(n) for n in names) + tests)
subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-parameter',
                '-g', str(path), '-o', str(root/'manual-charge-harness')], check=True)
subprocess.run([str(root/'manual-charge-harness')], check=True)
