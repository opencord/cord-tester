/**
 * Ciena application for cord tester to provision flows with ovs.
 * This is required as OVS onos driver does not support multi-table inserts.
 * This application takes a port pair configuration per group to provision flows.
 * To be used in simulation environments with subscriber tests.
 * On the target, cordmcast app should be used.
 */
package org.ciena.cordigmp;
