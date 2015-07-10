/*
 * Copyright (c) 2014-2015 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"io/ioutil"
	"testing"
)

func TestReadYAML(t *testing.T) {
	files, err := ioutil.ReadDir("testdata/valid-yaml")
	if err != nil {
		t.Errorf("ReadDir error: %v", err)
	}
	for _, file := range files {
		_, err := readYAML("testdata/valid-yaml/" + file.Name())
		if err != nil {
			t.Errorf("readYAML error: %v", err)
		}
	}
}

func TestReadYAMLErrors(t *testing.T) {
	files, err := ioutil.ReadDir("testdata/invalid-yaml")
	if err != nil {
		t.Errorf("ReadDir error: %v", err)
	}
	for _, file := range files {
		_, err := readYAML("testdata/invalid-yaml/" + file.Name())
		if err == nil {
			t.Errorf("readYAML should have errored out on file %v but didn't", file.Name())
		}
	}
}
